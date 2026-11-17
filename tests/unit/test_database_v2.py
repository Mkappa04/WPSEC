"""Schema v2: tabelle normalizzate, sigillo di immutabilità, vincoli SQL, migrazione v1,
andamento dei problemi nel tempo."""

import sqlite3
from datetime import timedelta

import pytest

from tests.helpers import FAST, lab_auth
from wpsec import __version__
from wpsec.core.models import (Confidence, Finding, FindingKind, FindingStatus, RemediationAdvice,
                               ScanOptions, ScanResult, Severity, StatusChange, now_utc)
from wpsec.core.scan import run_scan
from wpsec.database.schema import SCHEMA_VERSION, STATEMENTS_V1
from wpsec.database.store import ScanSealed, Store, TemplateConflict
from wpsec.knowledge.catalog import CATALOG_VERSION

S = FindingStatus
URL = "http://127.0.0.1:8081"


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "wpsec.sqlite3")


def _sql(store, query, *args):
    with sqlite3.connect(store.path) as c:
        c.execute("PRAGMA foreign_keys = ON")
        return c.execute(query, args).fetchall()


def _count(store, table, where="", *args):
    return _sql(store, f"SELECT COUNT(*) FROM {table} {where}", *args)[0][0]


def _scan(status="completed", minutes_ago=0, findings=()):
    r = ScanResult(platform_version=__version__, catalog_version=CATALOG_VERSION, target=URL,
                   host="127.0.0.1", authorization=lab_auth(URL), options=ScanOptions(),
                   status=status, started_at=now_utc() - timedelta(minutes=minutes_ago))
    r.findings.extend(findings)
    return r


def _f(check_id, status, sev=None, path="/"):
    f = Finding(check_id=check_id, title=check_id, category="wordpress",
                kind=FindingKind.MISCONFIGURATION, status=status, severity=sev, path=path,
                confidence=Confidence.HIGH)
    f.history.append(StatusChange(from_status=None, to_status=status, agent="test", reason="x"))
    return f


@pytest.fixture
def real_scan(mock_sites):
    """Scansione vera (pipeline completa) sul sito simulato vulnerabile."""
    url = mock_sites["wp-vuln"]
    return run_scan(url, lab_auth(url), ScanOptions(use_ai=False), FAST, ai=None)


# ------------------------------------------------------------ righe normalizzate

def test_scansione_completa_normalizzata(store, real_scan):
    store.save_scan(real_scan)
    sid = real_scan.id
    assert store.is_sealed(sid)
    assert _count(store, "findings", "WHERE scan_id=?", sid) == len(real_scan.findings)
    assert _count(store, "evidence", "WHERE scan_id=?", sid) == len(real_scan.evidence)
    assert _count(store, "agent_runs", "WHERE scan_id=?", sid) == len(real_scan.agents)
    assert _count(store, "trace_events", "WHERE scan_id=?", sid) == len(real_scan.trace)
    confirmed = [f for f in real_scan.findings if f.status == S.CONFIRMED]
    assert _count(store, "finding_remediation") == len(confirmed)
    # i sei header condividono un solo template: salvato una volta per versione del catalogo
    assert _count(store, "remediation_templates", "WHERE template_id='http.headers'") == 1
    # ogni cambio di stato è registrato (esito del controllo + decisione della validazione)
    users = next(f for f in real_scan.findings if f.check_id == "wp.users_rest")
    hist = store.status_history(users.id)
    assert [h["to_status"] for h in hist] == ["candidate", "confirmed"]
    assert hist[1]["agent"] == "evidence"
    # le evidenze che sostengono il risultato sono interrogabili
    evs = store.evidence_for_finding(users.id)
    assert {e["probe_id"] for e in evs} == {"wp_users_rest"}
    assert evs[0]["body_sha256"] and evs[0]["status_code"] == 200
    # la home sostiene più risultati (molti-a-molti)
    home = next(e for e in real_scan.evidence if e.probe_id == "home")
    assert _count(store, "finding_evidence", "WHERE evidence_id=?", home.id) > 3
    # il JSON completo resta identico
    assert store.get_scan(sid) == real_scan


def test_corpo_delle_risposte_mai_salvato(store, real_scan):
    store.save_scan(real_scan)
    cols = [r[1] for r in _sql(store, "PRAGMA table_info(evidence)")]
    assert "body" not in cols
    assert not _sql(store, "SELECT 1 FROM evidence WHERE excerpt LIKE '%<html%'")


def test_scansione_in_corso_solo_avanzamento(store):
    r = _scan(status="running", findings=[_f("wp.xmlrpc", S.CANDIDATE)])
    store.save_scan(r)
    assert not store.is_sealed(r.id)
    assert _count(store, "findings") == 0  # le righe figlie si scrivono solo alla fine
    r.status = "completed"
    store.save_scan(r)
    assert store.is_sealed(r.id) and _count(store, "findings") == 1


def test_scansioni_fallite_e_annullate_sigillate(store):
    for st in ("failed", "cancelled"):
        r = _scan(status=st)
        store.save_scan(r)
        assert store.is_sealed(r.id)


# ------------------------------------------------------------ immutabilità e vincoli

def test_scansione_sigillata_non_modificabile(store, real_scan):
    store.save_scan(real_scan)
    with pytest.raises(ScanSealed):
        store.save_scan(real_scan)
    fid = real_scan.findings[0].id
    eid = real_scan.evidence[0].id
    for q, args in (("UPDATE scans SET status='failed' WHERE id=?", (real_scan.id,)),
                    ("UPDATE findings SET status='not_present' WHERE id=?", (fid,)),
                    ("UPDATE evidence SET status_code=500 WHERE id=?", (eid,)),
                    ("INSERT INTO status_history (finding_id, seq, to_status, agent, timestamp) "
                     "VALUES (?, 99, 'confirmed', 'x', 'now')", (fid,)),
                    ("UPDATE remediation_templates SET title='x'", ())):
        with pytest.raises(sqlite3.DatabaseError, match="non"):
            _sql(store, q, *args)


def test_cancellazione_a_cascata(store, real_scan):
    store.save_scan(real_scan)
    store.delete_scan(real_scan.id)
    for t in ("findings", "evidence", "finding_evidence", "status_history", "agent_runs",
              "trace_events", "finding_remediation"):
        assert _count(store, t) == 0, t
    assert _count(store, "remediation_templates") > 0  # i template restano (versionati)
    assert _count(store, "authorizations") == 1        # le autorizzazioni non si cancellano


def test_vincoli_check(store):
    r = _scan(status="running")
    store.save_scan(r)
    with pytest.raises(sqlite3.IntegrityError):
        _sql(store, "UPDATE scans SET status='boh' WHERE id=?", r.id)
    with pytest.raises(sqlite3.IntegrityError):
        _sql(store, "INSERT INTO findings (id, scan_id, check_id, tracking_key, title, category, "
                    "kind, status, confidence) VALUES ('f1', ?, 'x', 'x|/', 't', 'http', 'k', "
                    "'vulnerabile', 'high')", r.id)
    with pytest.raises(sqlite3.IntegrityError):
        _sql(store, "INSERT INTO agent_runs (scan_id, name, display_name, state) "
                    "VALUES ('scan-inesistente', 'a', 'A', 'completed')")


def test_template_modificato_senza_nuova_versione(store):
    def with_rem(text):
        f = _f("wp.xmlrpc", S.CONFIRMED, Severity.MEDIUM)
        f.remediation = RemediationAdvice(template_id="wp.xmlrpc", title="Disabilitare",
                                          summary=text)
        return _scan(findings=[f])
    store.save_scan(with_rem("versione A"))
    with pytest.raises(TemplateConflict):
        store.save_scan(with_rem("versione B"))
    assert len(store.list_scans()) == 1  # la transazione fallita non lascia nulla


# ------------------------------------------------------------ andamento nel tempo

def test_andamento_dei_problemi(store):
    seq = [S.CONFIRMED, S.NOT_PRESENT, S.CONFIRMED]
    for i, st in enumerate(seq):
        store.save_scan(_scan(minutes_ago=30 - i * 10, findings=[
            _f("wp.xmlrpc", st, Severity.MEDIUM if st == S.CONFIRMED else None),
            _f("wp.users_rest", S.CONFIRMED if i == 0 else S.NOT_PRESENT, Severity.MEDIUM)]))
    store.save_scan(_scan(status="failed", findings=[_f("wp.xmlrpc", S.ERROR)]))  # ignorata
    t = {i["check_id"]: i for i in store.issue_timeline("127.0.0.1")}
    x = t["wp.xmlrpc"]
    assert x["scans"] == 3 and x["times_confirmed"] == 2 and x["reopened"] == 1
    assert x["current_status"] == "confirmed" and x["first_confirmed"] < x["last_confirmed"]
    u = t["wp.users_rest"]
    assert u["current_status"] == "not_present" and u["reopened"] == 0
    assert list(t)[0] == "wp.xmlrpc"  # prima i problemi aperti


def test_tracciamento_per_percorso(store):
    store.save_scan(_scan(findings=[_f("zap.10020", S.CONFIRMED, Severity.LOW, path="/a")]))
    keys = {i["tracking_key"] for i in store.issue_timeline("127.0.0.1")}
    assert keys == {"zap.10020|/a"}


def test_metriche_degli_agenti(store, real_scan):
    store.save_scan(real_scan)
    m = {x["name"]: x for x in store.agent_metrics([real_scan.id])}
    assert m["wordpress"]["completed"] == 1 and m["wordpress"]["requests"] > 0
    assert set(m) == {a.name for a in real_scan.agents}


# ------------------------------------------------------------ migrazione v1 -> v2

def test_migrazione_da_v1(tmp_path, real_scan):
    path = tmp_path / "vecchio.sqlite3"
    running = _scan(status="running")
    with sqlite3.connect(path) as c:
        for stmt in STATEMENTS_V1:
            c.execute(stmt)
        a = real_scan.authorization
        c.execute("INSERT INTO authorizations VALUES (?,?,?,?,?,?,?,?,?)",
                  (a.id, a.kind.value, a.target_url, "x", a.valid_from.isoformat(),
                   a.valid_until.isoformat(), 0, a.created_at.isoformat(), a.model_dump_json()))
        for r in (real_scan, running):
            c.execute("INSERT INTO scans (id, host, target, status, source, started_at, "
                      "authorization_id, platform_version, catalog_version, data) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (r.id, r.host, r.target, r.status, r.source, r.started_at.isoformat(),
                       r.authorization.id, r.platform_version, r.catalog_version, r.model_dump_json()))
        c.execute("PRAGMA user_version = 1")
    store = Store(path)
    assert _sql(store, "PRAGMA user_version")[0][0] == SCHEMA_VERSION
    assert store.get_scan(real_scan.id) == real_scan and store.is_sealed(real_scan.id)
    assert _count(store, "findings", "WHERE scan_id=?", real_scan.id) == len(real_scan.findings)
    assert store.get_authorization(real_scan.authorization.id) == real_scan.authorization
    assert not store.is_sealed(running.id)
    assert store.mark_interrupted() == 1 and store.is_sealed(running.id)


def test_migrazione_fallita_lascia_il_db_intatto(tmp_path):
    path = tmp_path / "rotto.sqlite3"
    with sqlite3.connect(path) as c:
        for stmt in STATEMENTS_V1:
            c.execute(stmt)
        c.execute("INSERT INTO scans (id, host, target, status, source, started_at, "
                  "authorization_id, platform_version, catalog_version, data) "
                  "VALUES ('s','h','t','completed','v4','x','a','4','c','{non json')")
        c.execute("PRAGMA user_version = 1")
    with pytest.raises(Exception):
        Store(path)
    with sqlite3.connect(path) as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == 1
        assert c.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
