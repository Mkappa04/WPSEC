"""Archivio SQLite e importazione delle scansioni v3."""

import json
import re
from datetime import timedelta
from pathlib import Path

import pytest

from tests.helpers import lab_auth
from wpsec import __version__
from wpsec.core.models import (Confidence, Finding, FindingKind, FindingStatus, ScanOptions,
                               ScanResult, Severity, now_utc)
from wpsec.database.legacy import (LegacyImportRefused, import_legacy_scan, redact_legacy_text)
from wpsec.database.store import NotFound, ScanSealed, Store
from wpsec.database.schema import SCHEMA_VERSION
from wpsec.knowledge.catalog import CATALOG_VERSION

ROOT = Path(__file__).resolve().parents[2]
URL = "http://127.0.0.1:8081"


def _result(status="completed", minutes_ago=0, findings=(), host_url=URL, **kw):
    r = ScanResult(platform_version=__version__, catalog_version=CATALOG_VERSION, target=host_url,
                   host="127.0.0.1", authorization=lab_auth(host_url), options=ScanOptions(**kw),
                   status=status, started_at=now_utc() - timedelta(minutes=minutes_ago))
    r.findings.extend(findings)
    return r


def _f(check_id, status, sev=None):
    return Finding(check_id=check_id, title=check_id, category="wordpress",
                   kind=FindingKind.INFORMATION_EXPOSURE, status=status, severity=sev,
                   confidence=Confidence.HIGH)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "db" / "wpsec.sqlite3")


# ------------------------------------------------------------ archivio

def test_salva_e_ricarica_scansione_identica(store):
    r = _result(findings=[_f("wp.users_rest", FindingStatus.CONFIRMED, Severity.MEDIUM)], label="x")
    store.save_scan(r)
    assert store.get_scan(r.id) == r


def test_aggiornamento_durante_l_esecuzione(store):
    r = _result(status="running")
    store.save_scan(r)
    r.status = "completed"
    r.findings.append(_f("wp.xmlrpc", FindingStatus.CONFIRMED, Severity.LOW))
    store.save_scan(r)
    rows = store.list_scans()
    assert len(rows) == 1 and rows[0]["status"] == "completed" and rows[0]["confirmed"] == 1
    assert rows[0]["severity"]["low"] == 1


def test_elenco_dal_piu_recente_e_filtri(store):
    old, new = _result(minutes_ago=10), _result(minutes_ago=1)
    store.save_scan(new)
    store.save_scan(old)
    assert [x["id"] for x in store.list_scans()] == [new.id, old.id]
    assert store.list_scans(host="altro.it") == []
    assert store.list_scans(status="failed") == []


def test_ultima_coppia_solo_completate(store):
    a, b, c = _result(minutes_ago=30), _result(minutes_ago=20), _result("failed", minutes_ago=5)
    for r in (a, b, c):
        store.save_scan(r)
    before, after = store.latest_pair("127.0.0.1")
    assert (before.id, after.id) == (a.id, b.id)


def test_ultima_coppia_insufficiente(store):
    store.save_scan(_result())
    with pytest.raises(NotFound):
        store.latest_pair("127.0.0.1")


def test_storico_di_un_controllo(store):
    store.save_scan(_result(minutes_ago=9, findings=[_f("wp.xmlrpc", FindingStatus.CONFIRMED)]))
    store.save_scan(_result(minutes_ago=1, findings=[_f("wp.xmlrpc", FindingStatus.NOT_PRESENT)]))
    h = store.finding_history("127.0.0.1", "wp.xmlrpc")
    assert [x["status"] for x in h] == ["confirmed", "not_present"]


def test_cancellazione_rimuove_anche_l_indice(store):
    r = _result(findings=[_f("wp.xmlrpc", FindingStatus.CONFIRMED)])
    store.save_scan(r)
    store.delete_scan(r.id)
    with pytest.raises(NotFound):
        store.get_scan(r.id)
    assert store.finding_history("127.0.0.1", "wp.xmlrpc") == []
    with pytest.raises(NotFound):
        store.delete_scan(r.id)


def test_scansioni_interrotte_marcate_fallite(store):
    r = _result(status="running")
    store.save_scan(r)
    assert store.mark_interrupted() == 1
    got = store.get_scan(r.id)
    assert got.status == "failed" and "interrotta" in got.error


def test_autorizzazioni_si_revocano_non_si_cancellano(store):
    a = store.save_authorization(lab_auth(URL))
    assert store.list_authorizations(only_valid=True)[0].id == a.id
    store.revoke_authorization(a.id)
    assert store.get_authorization(a.id).revoked is True
    assert store.list_authorizations(only_valid=True) == []
    assert len(store.list_authorizations()) == 1


def test_schema_versionato(store):
    import sqlite3
    with sqlite3.connect(store.path) as c:
        assert c.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        c.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(RuntimeError, match="più recente"):
        Store(store.path)


# ------------------------------------------------------------ importazione v3

LEGACY = sorted((ROOT / "scansioni").glob("127.0.0.1_*.json"))


@pytest.mark.skipif(not LEGACY, reason="nessuna scansione v3 di laboratorio")
def test_import_v3_laboratorio(store):
    r = import_legacy_scan(LEGACY[-1])
    assert r.source == "legacy-v3" and r.status == "completed"
    by = {f.legacy_id: f for f in r.findings}
    assert by["xmlrpc"].check_id == "wp.xmlrpc" and by["xmlrpc"].status == FindingStatus.CONFIRMED
    assert by["utenti"].status == FindingStatus.NOT_PRESENT
    assert "zap-sintesi" not in by and by["zap-20020"].category == "zap"
    assert by["zap-20020"].severity == Severity.HIGH and by["zap-20020"].cwe == "CWE-1395"
    assert any(n.agent == "legacy-v3" for f in r.findings for n in f.ai_notes)
    store.save_scan(r)
    assert store.get_scan(r.id) == r
    # stesso file importato due volte: stesso id, rifiutato (sigillata), nessun duplicato
    with pytest.raises(ScanSealed):
        store.save_scan(import_legacy_scan(LEGACY[-1]))
    assert len(store.list_scans()) == 1


def _scansione_v3_sintetica(cartella, bersaglio):
    """File v3 minimo, creato al momento: nessun dato reale nel repository."""
    host = bersaglio.split("://", 1)[1]
    p = cartella / f"{host}_20261113_123448.json"
    p.write_text(json.dumps({
        "scanner": "3.0", "data": "2026-11-13T12:34:48", "bersaglio": bersaglio,
        "risultati": [{"id": "xmlrpc", "titolo": "XML-RPC", "esito": "PROTETTO",
                       "gravita": "Media", "evidenza": "HTTP 403"}]}))
    return p


def test_import_v3_host_escluso(tmp_path):
    p = _scansione_v3_sintetica(tmp_path, "https://aternos.org")
    with pytest.raises(LegacyImportRefused, match="escluso"):
        import_legacy_scan(p, authorized_hosts={"aternos.org"})


def test_import_v3_host_reale_solo_se_dichiarato(tmp_path):
    p = tmp_path / "sito.example_1.json"
    p.write_text(json.dumps({
        "scanner": "3.0", "data": "2026-11-13T12:33:28", "bersaglio": "https://sito.example",
        "risultati": [{"id": "utenti", "titolo": "Utenti", "esito": "VULNERABILE", "gravita": "Media",
                       "evidenza": "1 utenti: slug='mariorossi'"},
                      {"id": "author", "titolo": "Autori", "esito": "VULNERABILE",
                       "gravita": "Bassa", "evidenza": "?author=1 -> /author/mariorossi/ "
                                                      "username 'mariorossi'"}]}))
    with pytest.raises(LegacyImportRefused, match="non indicato"):
        import_legacy_scan(p)
    r = import_legacy_scan(p, authorized_hosts={"SITO.example"})
    assert r.authorization.kind.value == "engagement" and "segnaposto" in r.authorization.notes
    assert "mariorossi" not in r.model_dump_json()


def test_username_reali_mai_importati_in_chiaro():
    for p in sorted((ROOT / "scansioni").glob("*.json")):
        raw = p.read_text(encoding="utf-8")
        names = set(re.findall(r"slug='([^']+)'", raw)) | set(re.findall(r"username '([^']+)'", raw))
        names = {n for n in names if len(n) > 2}
        try:
            r = import_legacy_scan(p, authorized_hosts={json.loads(raw)["bersaglio"].split("/")[2]})
        except LegacyImportRefused:
            continue
        dump = r.model_dump_json().replace(r.host, "")  # l'host resta nel target
        assert not [n for n in names if n in dump]


def test_redazione_testo_v3():
    assert redact_legacy_text("slug='admin' e username 'editor'") == "slug='a***n' e username 'e****r'"
