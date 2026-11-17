"""Schema SQLite della piattaforma (versione 2) e schema storico v1 (per la migrazione).

Struttura (vedi docs/DATABASE.md):

  authorizations ──< scans ──< agent_runs
                       ├──< evidence ─────────────┐
                       ├──< findings ──< finding_evidence (molti-a-molti)
                       │       ├──< status_history
                       │       ├──< ai_notes
                       │       └──  finding_remediation ──> remediation_templates
                       └──< trace_events
  vista finding_timeline: andamento di ogni problema (host + controllo + percorso) nel tempo

Integrità applicata dal database, non solo dal codice:
  - chiavi esterne con cancellazione a cascata dalla scansione;
  - CHECK su stati, gravità, confidenza, origine;
  - SIGILLO: una scansione terminata è immutabile (trigger). Le righe figlie si possono
    scrivere solo finché la scansione non è sigillata; la scansione sigillata si può solo
    cancellare per intero.
"""

SCHEMA_VERSION = 2

FINDING_STATUSES = ("candidate", "not_detected", "confirmed", "false_positive", "not_present",
                    "inconclusive", "not_applicable", "error", "info")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _in(values) -> str:
    return "(" + ", ".join(f"'{v}'" for v in values) + ")"


STATEMENTS_V2: list[str] = [
    """CREATE TABLE IF NOT EXISTS authorizations (
        id            TEXT PRIMARY KEY,
        kind          TEXT NOT NULL CHECK (kind IN ('engagement', 'lab')),
        target_url    TEXT NOT NULL,
        authorizer    TEXT NOT NULL,
        valid_from    TEXT NOT NULL,
        valid_until   TEXT NOT NULL,
        revoked       INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
        created_at    TEXT NOT NULL,
        data          TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS scans (
        id               TEXT PRIMARY KEY,
        authorization_id TEXT NOT NULL REFERENCES authorizations(id) ON DELETE RESTRICT,
        host             TEXT NOT NULL,
        target           TEXT NOT NULL,
        status           TEXT NOT NULL
                         CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
        source           TEXT NOT NULL CHECK (source IN ('v4', 'legacy-v3')),
        label            TEXT NOT NULL DEFAULT '',
        started_at       TEXT NOT NULL,
        finished_at      TEXT,
        duration_s       REAL NOT NULL DEFAULT 0,
        platform_version TEXT NOT NULL,
        catalog_version  TEXT NOT NULL,
        network_mode     TEXT NOT NULL DEFAULT '',
        user_agent       TEXT NOT NULL DEFAULT '',
        model_used       TEXT NOT NULL DEFAULT '',
        planner          TEXT NOT NULL DEFAULT 'deterministic',
        http_requests    INTEGER NOT NULL DEFAULT 0,
        confirmed        INTEGER NOT NULL DEFAULT 0,
        inconclusive     INTEGER NOT NULL DEFAULT 0,
        severity         TEXT NOT NULL DEFAULT '{}',
        executive_summary    TEXT NOT NULL DEFAULT '',
        executive_summary_ai INTEGER NOT NULL DEFAULT 0,
        error            TEXT,
        sealed           INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),
        raw_result       TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS scans_host_started ON scans(host, started_at)",
    "CREATE INDEX IF NOT EXISTS scans_status ON scans(status)",
    """CREATE TABLE IF NOT EXISTS agent_runs (
        scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        name         TEXT NOT NULL,
        display_name TEXT NOT NULL,
        uses_ai      INTEGER NOT NULL DEFAULT 0,
        state        TEXT NOT NULL
                     CHECK (state IN ('pending', 'running', 'completed', 'failed', 'skipped')),
        started_at   TEXT,
        finished_at  TEXT,
        duration_s   REAL NOT NULL DEFAULT 0,
        requests     INTEGER NOT NULL DEFAULT 0,
        findings     INTEGER NOT NULL DEFAULT 0,
        message      TEXT NOT NULL DEFAULT '',
        error        TEXT,
        PRIMARY KEY (scan_id, name)
    )""",
    """CREATE TABLE IF NOT EXISTS evidence (
        id               TEXT PRIMARY KEY,
        scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        probe_id         TEXT NOT NULL,
        method           TEXT NOT NULL,
        url              TEXT NOT NULL,
        status_code      INTEGER NOT NULL DEFAULT 0,
        headers          TEXT NOT NULL DEFAULT '{}',
        body_sha256      TEXT NOT NULL DEFAULT '',
        body_length      INTEGER NOT NULL DEFAULT 0,
        excerpt          TEXT NOT NULL DEFAULT '',
        final_url        TEXT NOT NULL DEFAULT '',
        redirect_chain   TEXT NOT NULL DEFAULT '[]',
        redirect_blocked TEXT NOT NULL DEFAULT '',
        elapsed_s        REAL NOT NULL DEFAULT 0,
        error            TEXT,
        via_proxy        TEXT NOT NULL DEFAULT '',
        from_cache       INTEGER NOT NULL DEFAULT 0,
        recheck          INTEGER NOT NULL DEFAULT 0,
        timestamp        TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS evidence_scan ON evidence(scan_id)",
    f"""CREATE TABLE IF NOT EXISTS findings (
        id           TEXT PRIMARY KEY,
        scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        check_id     TEXT NOT NULL,
        legacy_id    TEXT NOT NULL DEFAULT '',
        tracking_key TEXT NOT NULL,
        title        TEXT NOT NULL,
        category     TEXT NOT NULL,
        kind         TEXT NOT NULL,
        status       TEXT NOT NULL CHECK (status IN {_in(FINDING_STATUSES)}),
        confidence   TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
        path         TEXT NOT NULL DEFAULT '/',
        summary      TEXT NOT NULL DEFAULT '',
        details      TEXT NOT NULL DEFAULT '{{}}',
        agent        TEXT NOT NULL DEFAULT '',
        severity     TEXT CHECK (severity IS NULL OR severity IN {_in(SEVERITIES)}),
        priority     TEXT CHECK (priority IS NULL OR priority IN ('P1', 'P2', 'P3', 'P4')),
        impact       TEXT NOT NULL DEFAULT '',
        likelihood   TEXT NOT NULL DEFAULT '',
        rationale    TEXT NOT NULL DEFAULT '',
        cwe          TEXT NOT NULL DEFAULT '',
        cvss_vector  TEXT NOT NULL DEFAULT '',
        UNIQUE (scan_id, check_id)
    )""",
    "CREATE INDEX IF NOT EXISTS findings_tracking ON findings(tracking_key)",
    "CREATE INDEX IF NOT EXISTS findings_check_status ON findings(check_id, status)",
    """CREATE TABLE IF NOT EXISTS finding_evidence (
        finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        PRIMARY KEY (finding_id, evidence_id)
    )""",
    "CREATE INDEX IF NOT EXISTS finding_evidence_ev ON finding_evidence(evidence_id)",
    f"""CREATE TABLE IF NOT EXISTS status_history (
        finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        seq          INTEGER NOT NULL,
        from_status  TEXT CHECK (from_status IS NULL OR from_status IN {_in(FINDING_STATUSES)}),
        to_status    TEXT NOT NULL CHECK (to_status IN {_in(FINDING_STATUSES)}),
        agent        TEXT NOT NULL,
        reason       TEXT NOT NULL DEFAULT '',
        evidence_ids TEXT NOT NULL DEFAULT '[]',
        timestamp    TEXT NOT NULL,
        PRIMARY KEY (finding_id, seq)
    )""",
    """CREATE TABLE IF NOT EXISTS ai_notes (
        finding_id         TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        seq                INTEGER NOT NULL,
        agent              TEXT NOT NULL,
        model              TEXT NOT NULL,
        purpose            TEXT NOT NULL,
        text               TEXT NOT NULL,
        suggested_priority TEXT CHECK (suggested_priority IS NULL
                                       OR suggested_priority IN ('alta', 'media', 'bassa')),
        prompt_version     TEXT NOT NULL DEFAULT '',
        attempts           INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (finding_id, seq)
    )""",
    """CREATE TABLE IF NOT EXISTS remediation_templates (
        template_id     TEXT NOT NULL,
        catalog_version TEXT NOT NULL,
        title           TEXT NOT NULL,
        summary         TEXT NOT NULL,
        wordpress       TEXT NOT NULL DEFAULT '',
        apache          TEXT NOT NULL DEFAULT '',
        nginx           TEXT NOT NULL DEFAULT '',
        risks           TEXT NOT NULL DEFAULT '',
        verification    TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (template_id, catalog_version)
    )""",
    """CREATE TABLE IF NOT EXISTS finding_remediation (
        finding_id      TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
        template_id     TEXT NOT NULL,
        catalog_version TEXT NOT NULL,
        ai_context      TEXT NOT NULL DEFAULT '',
        refs            TEXT NOT NULL DEFAULT '[]',
        FOREIGN KEY (template_id, catalog_version)
            REFERENCES remediation_templates(template_id, catalog_version) ON DELETE RESTRICT
    )""",
    """CREATE TABLE IF NOT EXISTS trace_events (
        scan_id   TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        seq       INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        actor     TEXT NOT NULL,
        event     TEXT NOT NULL,
        detail    TEXT NOT NULL DEFAULT '',
        data      TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (scan_id, seq)
    )""",
    # ------------------------------------------------------------ immutabilità
    """CREATE TRIGGER IF NOT EXISTS scans_sealed_update
       BEFORE UPDATE ON scans WHEN OLD.sealed = 1
       BEGIN SELECT RAISE(ABORT, 'scansione sigillata: non modificabile'); END""",
    *[f"""CREATE TRIGGER IF NOT EXISTS {t}_sealed_{op.lower()}
       BEFORE {op} ON {t}
       WHEN (SELECT sealed FROM scans WHERE id = NEW.scan_id) = 1
       BEGIN SELECT RAISE(ABORT, 'scansione sigillata: non modificabile'); END"""
      for t in ("agent_runs", "evidence", "findings", "trace_events") for op in ("INSERT", "UPDATE")],
    *[f"""CREATE TRIGGER IF NOT EXISTS {t}_sealed_{op.lower()}
       BEFORE {op} ON {t}
       WHEN (SELECT s.sealed FROM findings f JOIN scans s ON s.id = f.scan_id
             WHERE f.id = NEW.finding_id) = 1
       BEGIN SELECT RAISE(ABORT, 'scansione sigillata: non modificabile'); END"""
      for t in ("finding_evidence", "status_history", "ai_notes", "finding_remediation")
      for op in ("INSERT", "UPDATE")],
    """CREATE TRIGGER IF NOT EXISTS remediation_templates_immutable
       BEFORE UPDATE ON remediation_templates
       BEGIN SELECT RAISE(ABORT, 'i template di una versione del catalogo non si modificano'); END""",
    # ------------------------------------------------------------ andamento nel tempo
    """CREATE VIEW IF NOT EXISTS finding_timeline AS
       SELECT s.host, f.tracking_key, f.check_id, f.legacy_id, f.title, f.path,
              s.id AS scan_id, s.started_at, s.source, s.label, f.status, f.severity, f.id AS finding_id
       FROM findings f JOIN scans s ON s.id = f.scan_id
       WHERE s.sealed = 1 AND s.status = 'completed'""",
]

# Schema v1 (commit aab5261): serve solo a riconoscerlo e ai test della migrazione.
STATEMENTS_V1: list[str] = [
    """CREATE TABLE IF NOT EXISTS authorizations (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, target_url TEXT NOT NULL, authorizer TEXT NOT NULL,
        valid_from TEXT NOT NULL, valid_until TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL, data TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, host TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
        source TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL,
        finished_at TEXT, authorization_id TEXT NOT NULL, platform_version TEXT NOT NULL,
        catalog_version TEXT NOT NULL, confirmed INTEGER NOT NULL DEFAULT 0,
        inconclusive INTEGER NOT NULL DEFAULT 0, severity TEXT NOT NULL DEFAULT '{}',
        data TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS findings (
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE, check_id TEXT NOT NULL,
        legacy_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, severity TEXT,
        title TEXT NOT NULL, PRIMARY KEY (scan_id, check_id))""",
]
