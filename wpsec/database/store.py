"""Archivio SQLite di autorizzazioni e scansioni (solo libreria standard).

Scelte:
  - il risultato completo è salvato come JSON validato (ScanResult): una sola fonte di
    verità, ricaricabile e confrontabile anche con versioni future dello schema;
  - le colonne e la tabella `findings` sono un INDICE per elenchi e storico (dashboard,
    confronti), sempre ricalcolato dal JSON a ogni salvataggio;
  - una connessione per operazione (thread-safe, adatto a FastAPI e all'orchestratore);
  - le autorizzazioni non si cancellano: si revocano (tracciabilità).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from wpsec.core.models import Authorization, ScanResult, now_utc

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS authorizations (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    target_url    TEXT NOT NULL,
    authorizer    TEXT NOT NULL,
    valid_from    TEXT NOT NULL,
    valid_until   TEXT NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    data          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id               TEXT PRIMARY KEY,
    host             TEXT NOT NULL,
    target           TEXT NOT NULL,
    status           TEXT NOT NULL,
    source           TEXT NOT NULL,
    label            TEXT NOT NULL DEFAULT '',
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    authorization_id TEXT NOT NULL,
    platform_version TEXT NOT NULL,
    catalog_version  TEXT NOT NULL,
    confirmed        INTEGER NOT NULL DEFAULT 0,
    inconclusive     INTEGER NOT NULL DEFAULT 0,
    severity         TEXT NOT NULL DEFAULT '{}',
    data             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_host_started ON scans(host, started_at);
CREATE TABLE IF NOT EXISTS findings (
    scan_id    TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id   TEXT NOT NULL,
    legacy_id  TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL,
    severity   TEXT,
    title      TEXT NOT NULL,
    PRIMARY KEY (scan_id, check_id)
);
CREATE INDEX IF NOT EXISTS findings_check ON findings(check_id, status);
"""


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


class NotFound(KeyError):
    pass


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)  # file su disco: ogni operazione apre la propria connessione
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            version = c.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(f"database creato da una versione più recente (schema {version})")
            c.executescript(_SCHEMA)
            c.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------ autorizzazioni
    def save_authorization(self, auth: Authorization) -> Authorization:
        with self._conn() as c:
            c.execute(
                "INSERT INTO authorizations (id, kind, target_url, authorizer, valid_from, "
                "valid_until, revoked, created_at, data) VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET revoked=excluded.revoked, data=excluded.data",
                (auth.id, auth.kind.value, auth.target_url,
                 f"{auth.authorizer_name} ({auth.authorizer_role})", _iso(auth.valid_from),
                 _iso(auth.valid_until), int(auth.revoked), _iso(auth.created_at),
                 auth.model_dump_json()))
        return auth

    def get_authorization(self, auth_id: str) -> Authorization:
        with self._conn() as c:
            row = c.execute("SELECT data FROM authorizations WHERE id=?", (auth_id,)).fetchone()
        if row is None:
            raise NotFound(f"autorizzazione {auth_id} inesistente")
        return Authorization.model_validate_json(row["data"])

    def list_authorizations(self, only_valid: bool = False) -> list[Authorization]:
        with self._conn() as c:
            rows = c.execute("SELECT data FROM authorizations ORDER BY created_at DESC").fetchall()
        auths = [Authorization.model_validate_json(r["data"]) for r in rows]
        if only_valid:
            now = now_utc()
            auths = [a for a in auths if a.is_valid_at(now)[0]]
        return auths

    def revoke_authorization(self, auth_id: str) -> Authorization:
        auth = self.get_authorization(auth_id)
        auth.revoked = True
        return self.save_authorization(auth)

    # ------------------------------------------------------------ scansioni
    def save_scan(self, result: ScanResult) -> None:
        """Inserisce o aggiorna (anche durante l'esecuzione, per l'avanzamento)."""
        counts = result.counts()
        with self._conn() as c:
            c.execute(
                "INSERT INTO scans (id, host, target, status, source, label, started_at, "
                "finished_at, authorization_id, platform_version, catalog_version, confirmed, "
                "inconclusive, severity, data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET status=excluded.status, "
                "finished_at=excluded.finished_at, confirmed=excluded.confirmed, "
                "inconclusive=excluded.inconclusive, severity=excluded.severity, "
                "label=excluded.label, data=excluded.data",
                (result.id, result.host, result.target, result.status, result.source,
                 result.options.label, _iso(result.started_at), _iso(result.finished_at),
                 result.authorization.id, result.platform_version, result.catalog_version,
                 counts.get("confirmed", 0), counts.get("inconclusive", 0),
                 json.dumps(result.severity_counts()), result.model_dump_json()))
            c.execute("DELETE FROM findings WHERE scan_id=?", (result.id,))
            c.executemany(
                "INSERT INTO findings (scan_id, check_id, legacy_id, status, severity, title) "
                "VALUES (?,?,?,?,?,?)",
                [(result.id, f.check_id, f.legacy_id, f.status.value,
                  f.severity.value if f.severity else None, f.title) for f in result.findings])

    def get_scan(self, scan_id: str) -> ScanResult:
        with self._conn() as c:
            row = c.execute("SELECT data FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            raise NotFound(f"scansione {scan_id} inesistente")
        return ScanResult.model_validate_json(row["data"])

    def list_scans(self, host: str | None = None, limit: int = 50,
                   status: str | None = None) -> list[dict]:
        """Elenco leggero (senza il JSON completo), dal più recente."""
        sql = ("SELECT id, host, target, status, source, label, started_at, finished_at, "
               "confirmed, inconclusive, severity, platform_version FROM scans")
        where, args = [], []
        if host:
            where.append("host=?")
            args.append(host.lower())
        if status:
            where.append("status=?")
            args.append(status)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY started_at DESC LIMIT ?"
        args.append(int(limit))
        with self._conn() as c:
            rows = c.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["severity"] = json.loads(d["severity"])
            out.append(d)
        return out

    def latest_pair(self, host: str) -> tuple[ScanResult, ScanResult]:
        """Le ultime due scansioni COMPLETATE di un host: (prima, dopo)."""
        rows = self.list_scans(host=host, limit=2, status="completed")
        if len(rows) < 2:
            raise NotFound(f"servono almeno due scansioni completate di {host}")
        return self.get_scan(rows[1]["id"]), self.get_scan(rows[0]["id"])

    def finding_history(self, host: str, check_id: str) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT s.id AS scan_id, s.started_at, s.source, f.status, f.severity "
                "FROM findings f JOIN scans s ON s.id = f.scan_id "
                "WHERE s.host=? AND (f.check_id=? OR f.legacy_id=?) ORDER BY s.started_at",
                (host.lower(), check_id, check_id)).fetchall()
        return [dict(r) for r in rows]

    def delete_scan(self, scan_id: str) -> None:
        with self._conn() as c:
            cur = c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        if cur.rowcount == 0:
            raise NotFound(f"scansione {scan_id} inesistente")

    def mark_interrupted(self) -> int:
        """All'avvio: le scansioni rimaste 'running' (processo terminato) diventano 'failed'."""
        n = 0
        for row in self.list_scans(status="running", limit=1000):
            r = self.get_scan(row["id"])
            r.status, r.error = "failed", "interrotta: il processo è terminato durante la scansione"
            self.save_scan(r)
            n += 1
        return n
