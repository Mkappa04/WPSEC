"""Archivio SQLite di autorizzazioni e scansioni (schema v2, solo libreria standard).

Due livelli, entrambi scritti nella STESSA transazione:
  - `scans.raw_result`: lo ScanResult completo (JSON validato), archivio fedele da cui si
    rigenerano report e confronti e si ricostruiscono le tabelle in caso di migrazione;
  - tabelle normalizzate (agent_runs, evidence, findings, finding_evidence, status_history,
    ai_notes, finding_remediation, remediation_templates, trace_events) per interrogazioni,
    storico e metriche.

Ciclo di vita di una scansione nell'archivio:
  - durante l'esecuzione: si aggiornano solo la riga di `scans` e `agent_runs` (avanzamento);
  - alla fine (completed/failed/cancelled): scrittura completa delle righe figlie e SIGILLO.
    Da quel momento la scansione è immutabile (trigger SQL): si può solo cancellare intera.

L'interfaccia pubblica (save_scan, get_scan, list_scans, ...) è la stessa dello schema v1.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from wpsec.core.models import Authorization, ScanResult, now_utc
from wpsec.database.schema import SCHEMA_VERSION, STATEMENTS_V2

FINAL_STATES = {"completed", "failed", "cancelled"}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _j(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def tracking_key(check_id: str, path: str) -> str:
    """Identità di un problema fra scansioni dello stesso host (l'host è nella scansione)."""
    return f"{check_id}|{path or '/'}"


class NotFound(KeyError):
    pass


class ScanSealed(Exception):
    """Tentativo di modificare una scansione già conclusa e sigillata."""


class TemplateConflict(Exception):
    """Stesso template e stessa versione del catalogo ma contenuto diverso: il catalogo è
    stato modificato senza aggiornare CATALOG_VERSION."""


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)  # file su disco: ogni operazione apre la propria connessione
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._tx() as c:
            version = c.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(f"database creato da una versione più recente (schema {version})")
            if version == 1:
                from wpsec.database.migrations import migrate_v1_to_v2
                migrate_v1_to_v2(c, self._write_scan)
            else:
                for stmt in STATEMENTS_V2:
                    c.execute(stmt)
            c.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ------------------------------------------------------------ connessioni
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def _tx(self):
        """Transazione di scrittura (BEGIN IMMEDIATE): tutto o niente."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    @contextmanager
    def _read(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------ autorizzazioni
    @staticmethod
    def _upsert_authorization(c, auth: Authorization, update: bool = True):
        c.execute(
            "INSERT INTO authorizations (id, kind, target_url, authorizer, valid_from, valid_until, "
            "revoked, created_at, data) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO "
            + ("UPDATE SET revoked=excluded.revoked, data=excluded.data" if update else "NOTHING"),
            (auth.id, auth.kind.value, auth.target_url,
             f"{auth.authorizer_name} ({auth.authorizer_role})", _iso(auth.valid_from),
             _iso(auth.valid_until), int(auth.revoked), _iso(auth.created_at), auth.model_dump_json()))

    def save_authorization(self, auth: Authorization) -> Authorization:
        with self._tx() as c:
            self._upsert_authorization(c, auth)
        return auth

    def get_authorization(self, auth_id: str) -> Authorization:
        with self._read() as c:
            row = c.execute("SELECT data FROM authorizations WHERE id=?", (auth_id,)).fetchone()
        if row is None:
            raise NotFound(f"autorizzazione {auth_id} inesistente")
        return Authorization.model_validate_json(row["data"])

    def list_authorizations(self, only_valid: bool = False) -> list[Authorization]:
        with self._read() as c:
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

    # ------------------------------------------------------------ scrittura delle scansioni
    def save_scan(self, result: ScanResult) -> None:
        """Salva l'avanzamento (scansione in corso) o il risultato finale (e lo sigilla).
        Solleva ScanSealed se la scansione è già stata sigillata."""
        with self._tx() as c:
            self._write_scan(c, result)

    def _write_scan(self, c: sqlite3.Connection, r: ScanResult) -> None:
        row = c.execute("SELECT sealed FROM scans WHERE id=?", (r.id,)).fetchone()
        if row is not None and row["sealed"]:
            raise ScanSealed(f"la scansione {r.id} è conclusa e non può essere modificata")
        # l'autorizzazione usata viene registrata se manca (es. segnaposto delle scansioni v3);
        # una già presente non viene sovrascritta (la revoca resta)
        self._upsert_authorization(c, r.authorization, update=False)
        counts = r.counts()
        values = dict(
            id=r.id, authorization_id=r.authorization.id, host=r.host, target=r.target,
            status=r.status, source=r.source, label=r.options.label, started_at=_iso(r.started_at),
            finished_at=_iso(r.finished_at), duration_s=r.duration_s,
            platform_version=r.platform_version, catalog_version=r.catalog_version,
            network_mode=r.network_mode, user_agent=r.user_agent, model_used=r.model_used,
            planner=r.options.planner, http_requests=int(r.stats.get("http", {}).get("requests", 0)),
            confirmed=counts.get("confirmed", 0), inconclusive=counts.get("inconclusive", 0),
            severity=_j(r.severity_counts()), executive_summary=r.executive_summary,
            executive_summary_ai=int(r.executive_summary_ai), error=r.error,
            raw_result=r.model_dump_json())
        cols = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        updates = ", ".join(f"{k}=excluded.{k}" for k in values if k != "id")
        c.execute(f"INSERT INTO scans ({cols}) VALUES ({marks}) ON CONFLICT(id) DO UPDATE SET {updates}",
                  list(values.values()))

        c.execute("DELETE FROM agent_runs WHERE scan_id=?", (r.id,))
        c.executemany(
            "INSERT INTO agent_runs (scan_id, name, display_name, uses_ai, state, started_at, "
            "finished_at, duration_s, requests, findings, message, error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [(r.id, a.name, a.display_name, int(a.uses_ai), a.state.value, _iso(a.started_at),
              _iso(a.finished_at), a.duration_s, a.requests, a.findings, a.message, a.error)
             for a in r.agents])

        if r.status in FINAL_STATES:
            self._write_details(c, r)
            c.execute("UPDATE scans SET sealed=1 WHERE id=?", (r.id,))

    def _write_details(self, c: sqlite3.Connection, r: ScanResult) -> None:
        # una scansione non ancora sigillata non ha righe figlie: si riparte da zero per sicurezza
        c.execute("DELETE FROM findings WHERE scan_id=?", (r.id,))
        c.execute("DELETE FROM evidence WHERE scan_id=?", (r.id,))
        c.execute("DELETE FROM trace_events WHERE scan_id=?", (r.id,))

        c.executemany(
            "INSERT INTO evidence (id, scan_id, probe_id, method, url, status_code, headers, "
            "body_sha256, body_length, excerpt, final_url, redirect_chain, redirect_blocked, "
            "elapsed_s, error, via_proxy, from_cache, recheck, timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(e.id, r.id, e.probe_id, e.method, e.url, e.status_code, _j(e.headers), e.body_sha256,
              e.body_length, e.excerpt, e.final_url, _j(e.redirect_chain), e.redirect_blocked,
              e.elapsed_s, e.error, e.via_proxy, int(e.from_cache), int(e.recheck), _iso(e.timestamp))
             for e in r.evidence])
        known_evidence = {e.id for e in r.evidence}

        for f in r.findings:
            c.execute(
                "INSERT INTO findings (id, scan_id, check_id, legacy_id, tracking_key, title, "
                "category, kind, status, confidence, path, summary, details, agent, severity, "
                "priority, impact, likelihood, rationale, cwe, cvss_vector) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f.id, r.id, f.check_id, f.legacy_id, tracking_key(f.check_id, f.path), f.title,
                 f.category, f.kind.value, f.status.value, f.confidence.value, f.path, f.summary,
                 _j(f.details), f.agent, f.severity.value if f.severity else None, f.priority,
                 f.impact, f.likelihood, f.rationale, f.cwe, f.cvss_vector))
            c.executemany("INSERT OR IGNORE INTO finding_evidence (finding_id, evidence_id) VALUES (?,?)",
                          [(f.id, e) for e in f.evidence_ids if e in known_evidence])
            c.executemany(
                "INSERT INTO status_history (finding_id, seq, from_status, to_status, agent, reason, "
                "evidence_ids, timestamp) VALUES (?,?,?,?,?,?,?,?)",
                [(f.id, i, h.from_status.value if h.from_status else None, h.to_status.value,
                  h.agent, h.reason, _j(h.evidence_ids), _iso(h.timestamp))
                 for i, h in enumerate(f.history)])
            c.executemany(
                "INSERT INTO ai_notes (finding_id, seq, agent, model, purpose, text, "
                "suggested_priority, prompt_version, attempts) VALUES (?,?,?,?,?,?,?,?,?)",
                [(f.id, i, n.agent, n.model, n.purpose, n.text, n.suggested_priority,
                  n.prompt_version, n.attempts) for i, n in enumerate(f.ai_notes)])
            if f.remediation is not None:
                self._write_template(c, f.remediation, r.catalog_version)
                c.execute("INSERT INTO finding_remediation (finding_id, template_id, catalog_version, "
                          "ai_context, refs) VALUES (?,?,?,?,?)",
                          (f.id, f.remediation.template_id, r.catalog_version,
                           f.remediation.ai_context, _j(list(f.remediation.references))))

        c.executemany(
            "INSERT INTO trace_events (scan_id, seq, timestamp, actor, event, detail, data) "
            "VALUES (?,?,?,?,?,?,?)",
            [(r.id, i, _iso(t.timestamp), t.actor, t.event, t.detail, _j(t.data))
             for i, t in enumerate(r.trace)])

    @staticmethod
    def _write_template(c, adv, catalog_version: str):
        fields = (adv.title, adv.summary, adv.wordpress, adv.apache, adv.nginx, adv.risks,
                  adv.verification)
        existing = c.execute(
            "SELECT title, summary, wordpress, apache, nginx, risks, verification "
            "FROM remediation_templates WHERE template_id=? AND catalog_version=?",
            (adv.template_id, catalog_version)).fetchone()
        if existing is None:
            c.execute("INSERT INTO remediation_templates (template_id, catalog_version, title, "
                      "summary, wordpress, apache, nginx, risks, verification) "
                      "VALUES (?,?,?,?,?,?,?,?,?)", (adv.template_id, catalog_version, *fields))
        elif tuple(existing) != fields:
            raise TemplateConflict(
                f"template {adv.template_id} diverso a parità di versione del catalogo "
                f"({catalog_version}): aggiornare CATALOG_VERSION")

    # ------------------------------------------------------------ lettura
    def get_scan(self, scan_id: str) -> ScanResult:
        with self._read() as c:
            row = c.execute("SELECT raw_result FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            raise NotFound(f"scansione {scan_id} inesistente")
        return ScanResult.model_validate_json(row["raw_result"])

    def is_sealed(self, scan_id: str) -> bool:
        with self._read() as c:
            row = c.execute("SELECT sealed FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            raise NotFound(f"scansione {scan_id} inesistente")
        return bool(row["sealed"])

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
        with self._read() as c:
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
        with self._read() as c:
            rows = c.execute(
                "SELECT s.id AS scan_id, s.started_at, s.source, f.status, f.severity "
                "FROM findings f JOIN scans s ON s.id = f.scan_id "
                "WHERE s.host=? AND (f.check_id=? OR f.legacy_id=?) ORDER BY s.started_at",
                (host.lower(), check_id, check_id)).fetchall()
        return [dict(r) for r in rows]

    def issue_timeline(self, host: str) -> list[dict]:
        """Andamento di ogni problema dell'host sulle scansioni completate (dalla vista
        finding_timeline): prima e ultima conferma, stato attuale, ricomparse."""
        with self._read() as c:
            rows = c.execute("SELECT * FROM finding_timeline WHERE host=? ORDER BY started_at",
                             (host.lower(),)).fetchall()
        issues: dict[str, dict] = {}
        for r in rows:
            it = issues.setdefault(r["tracking_key"], {
                "tracking_key": r["tracking_key"], "check_id": r["check_id"], "title": r["title"],
                "path": r["path"], "first_confirmed": None, "last_confirmed": None,
                "times_confirmed": 0, "reopened": 0, "scans": 0, "current_status": None,
                "current_severity": None, "history": []})
            was_fixed = it["current_status"] in ("not_present", "false_positive") \
                and it["times_confirmed"] > 0
            it["scans"] += 1
            it["current_status"], it["current_severity"] = r["status"], r["severity"]
            it["history"].append({"scan_id": r["scan_id"], "started_at": r["started_at"],
                                  "source": r["source"], "label": r["label"],
                                  "status": r["status"], "severity": r["severity"]})
            if r["status"] == "confirmed":
                it["times_confirmed"] += 1
                it["first_confirmed"] = it["first_confirmed"] or r["started_at"]
                it["last_confirmed"] = r["started_at"]
                if was_fixed:
                    it["reopened"] += 1
        return sorted(issues.values(), key=lambda i: (i["current_status"] != "confirmed", i["check_id"]))

    def evidence_for_finding(self, finding_id: str) -> list[dict]:
        """Le evidenze (richieste realmente eseguite) che sostengono un risultato."""
        with self._read() as c:
            rows = c.execute(
                "SELECT e.* FROM finding_evidence fe JOIN evidence e ON e.id = fe.evidence_id "
                "WHERE fe.finding_id=? ORDER BY e.timestamp", (finding_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["headers"], d["redirect_chain"] = json.loads(d["headers"]), json.loads(d["redirect_chain"])
            out.append(d)
        return out

    def status_history(self, finding_id: str) -> list[dict]:
        with self._read() as c:
            rows = c.execute("SELECT * FROM status_history WHERE finding_id=? ORDER BY seq",
                             (finding_id,)).fetchall()
        return [{**dict(r), "evidence_ids": json.loads(r["evidence_ids"])} for r in rows]

    def remediation_template(self, template_id: str, catalog_version: str) -> dict:
        with self._read() as c:
            row = c.execute("SELECT * FROM remediation_templates WHERE template_id=? AND "
                            "catalog_version=?", (template_id, catalog_version)).fetchone()
        if row is None:
            raise NotFound(f"template {template_id} ({catalog_version}) inesistente")
        return dict(row)

    def agent_metrics(self, scan_ids: list[str] | None = None) -> list[dict]:
        """Durata media, richieste e esiti per agente (per il benchmark)."""
        sql = ("SELECT name, COUNT(*) AS runs, AVG(duration_s) AS avg_duration_s, "
               "SUM(requests) AS requests, SUM(state='completed') AS completed, "
               "SUM(state='failed') AS failed, SUM(state='skipped') AS skipped FROM agent_runs")
        args: list = []
        if scan_ids:
            sql += f" WHERE scan_id IN ({','.join('?' for _ in scan_ids)})"
            args = list(scan_ids)
        sql += " GROUP BY name ORDER BY name"
        with self._read() as c:
            return [dict(r) for r in c.execute(sql, args).fetchall()]

    # ------------------------------------------------------------ cancellazione e ripristino
    def delete_scan(self, scan_id: str) -> None:
        with self._tx() as c:
            cur = c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        if cur.rowcount == 0:
            raise NotFound(f"scansione {scan_id} inesistente")

    def mark_interrupted(self) -> int:
        """All'avvio: le scansioni non sigillate rimaste 'running' (processo terminato)
        diventano 'failed' e vengono sigillate."""
        with self._read() as c:
            ids = [r["id"] for r in c.execute(
                "SELECT id FROM scans WHERE sealed=0 AND status IN ('running', 'pending')").fetchall()]
        for scan_id in ids:
            r = self.get_scan(scan_id)
            r.status, r.error = "failed", "interrotta: il processo è terminato durante la scansione"
            r.finished_at = r.finished_at or now_utc()
            self.save_scan(r)
        return len(ids)
