"""Pipeline completa (run_scan) sui siti simulati: esiti attesi, correzione degli errori
noti della v3 su wp-tricky, controlli preliminari, IA locale simulata."""

from datetime import timedelta

import pytest

from tests.helpers import FAST, lab_auth
from wpsec.ai.assistant import OllamaAssistant
from wpsec.ai.ollama_client import OllamaClient
from wpsec.core.models import (AgentState, Authorization, AuthorizationKind, FindingStatus, Origin,
                               ScanOptions, Severity, now_utc)
from wpsec.core.scan import ScanRefused, run_scan

S = FindingStatus
NO_AI = ScanOptions(use_ai=False)
WP_CHECKS = ("wp.users_rest", "wp.author_enum", "wp.xmlrpc", "wp.version_disclosure",
             "wp.directory_listing")

# esiti attesi dei controlli WordPress (stessi profili di lab/mock_wp.py)
EXPECTED = {
    "wp-vuln": dict.fromkeys(WP_CHECKS, S.CONFIRMED),
    "wp-hard": dict.fromkeys(WP_CHECKS, S.NOT_PRESENT),
    "wp-mixed": {"wp.users_rest": S.CONFIRMED, "wp.author_enum": S.CONFIRMED,
                 "wp.xmlrpc": S.NOT_PRESENT, "wp.version_disclosure": S.NOT_PRESENT,
                 "wp.directory_listing": S.CONFIRMED},
    # i tre errori della v3 corretti: WAF -> inconcludente, feed -> confermato,
    # "Index of" in un articolo -> falso positivo
    "wp-tricky": {"wp.users_rest": S.INCONCLUSIVE, "wp.author_enum": S.NOT_PRESENT,
                  "wp.xmlrpc": S.NOT_PRESENT, "wp.version_disclosure": S.CONFIRMED,
                  "wp.directory_listing": S.FALSE_POSITIVE},
}


def _scan(url, options=NO_AI, **kw):
    return run_scan(url, lab_auth(url), options, FAST, ai=kw.pop("ai", None), **kw)


def _status(result):
    return {f.check_id: f.status for f in result.findings}


@pytest.mark.parametrize("sito", sorted(EXPECTED))
def test_esiti_wordpress(mock_sites, sito):
    r = _scan(mock_sites[sito])
    assert r.status == "completed"
    st = _status(r)
    assert {k: st[k] for k in WP_CHECKS} == EXPECTED[sito]
    assert all(a.state == AgentState.COMPLETED for a in r.agents)


def test_nessun_candidato_resta_senza_decisione(mock_sites):
    for url in mock_sites.values():
        r = _scan(url)
        assert not [f for f in r.findings if f.status in (S.CANDIDATE, S.NOT_DETECTED)]


def test_confermati_hanno_evidenze_gravita_e_correzione(mock_sites):
    r = _scan(mock_sites["wp-vuln"])
    ev_ids = {e.id for e in r.evidence}
    for f in r.findings:
        if f.status == S.CONFIRMED:
            assert f.evidence_ids and set(f.evidence_ids) <= ev_ids
            assert f.severity is not None and f.priority
            assert f.remediation is not None and f.remediation.verification


def test_username_mascherati_nelle_evidenze(mock_sites):
    r = _scan(mock_sites["wp-vuln"])
    f = next(f for f in r.findings if f.check_id == "wp.users_rest")
    assert "admin" not in f.summary and "a***n" in f.summary
    assert all("admin" not in e.excerpt for e in r.evidence)


def test_home_scaricata_una_sola_volta(mock_sites):
    r = _scan(mock_sites["wp-vuln"])
    assert sum(1 for e in r.evidence if e.probe_id == "home" and not e.from_cache) == 1


def test_correlazione_utenti_e_xmlrpc(mock_sites):
    r = _scan(mock_sites["wp-vuln"])
    users = next(f for f in r.findings if f.check_id == "wp.users_rest")
    assert users.severity == Severity.MEDIUM and "XML-RPC" in users.likelihood


def test_wp_non_rilevato_salta_l_agente(mock_sites):
    # sito simulato con un percorso che non ha WordPress: si usa un server senza indicatori
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"<html>sito statico</html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        r = _scan(url)
        wp = next(a for a in r.agents if a.name == "wordpress")
        assert wp.state == AgentState.SKIPPED
        assert any("WordPress" in lim for lim in r.stats["limitations"])
        r2 = _scan(url, ScanOptions(use_ai=False, force_wordpress=True))
        assert next(a for a in r2.agents if a.name == "wordpress").state == AgentState.COMPLETED
    finally:
        srv.shutdown()


def test_target_irraggiungibile(unused_port):
    url = f"http://127.0.0.1:{unused_port}"
    r = _scan(url)
    assert r.status == "completed"
    st = {a.name: a.state for a in r.agents}
    assert st["recon"] == AgentState.FAILED
    assert st["wordpress"] == AgentState.SKIPPED and st["http"] == AgentState.SKIPPED
    assert st["reporting"] == AgentState.COMPLETED
    assert r.executive_summary


# ------------------------------------------------------------ controlli preliminari

def test_autorizzazione_scaduta_rifiutata(mock_sites):
    url = mock_sites["wp-vuln"]
    auth = lab_auth(url, valid_until=now_utc() - timedelta(minutes=1))
    with pytest.raises(ScanRefused, match="scaduta"):
        run_scan(url, auth, NO_AI, FAST, ai=None)


def test_target_fuori_perimetro_rifiutato(mock_sites):
    auth = lab_auth(mock_sites["wp-vuln"])
    with pytest.raises(ScanRefused, match="perimetro"):
        run_scan(mock_sites["wp-hard"], auth, NO_AI, FAST, ai=None)


def test_scansione_attiva_solo_in_laboratorio():
    url = "https://example.org"
    auth = Authorization(kind=AuthorizationKind.ENGAGEMENT, target_url=url,
                         scope=[Origin.from_url(url)], authorizer_name="Proprietario",
                         authorizer_role="Titolare", operator="Studente",
                         valid_from=now_utc() - timedelta(hours=1),
                         valid_until=now_utc() + timedelta(hours=1))
    with pytest.raises(ScanRefused, match="laboratorio"):
        run_scan(url, auth, ScanOptions(use_ai=False, zap_active=True), FAST, ai=None)


def test_annullamento_prima_dell_avvio(mock_sites):
    import threading
    ev = threading.Event()
    ev.set()
    r = _scan(mock_sites["wp-vuln"], cancel_event=ev)
    assert r.status == "cancelled" and r.stats["http"]["requests"] == 0


# ------------------------------------------------------------ IA simulata

ALL_FIELDS = ('{"spiegazione": "Gli username esposti facilitano gli attacchi alle password.", '
              '"priorita": "alta", "contesto": "Serve a ridurre la superficie di attacco del sito.", '
              '"sintesi": "Il sito presenta alcune esposizioni informative e configurazioni deboli '
              'da correggere con priorità media."}')


def _assistant(fake, retries=1):
    return OllamaAssistant(OllamaClient(fake.url, timeout=5), "qwen3.5:4b",
                           FAST.with_overrides(ai_retries=retries))


def test_pipeline_con_ia_simulata(mock_sites, fake_ollama):
    fake_ollama.default = ALL_FIELDS
    ai = _assistant(fake_ollama)
    r = _scan(mock_sites["wp-vuln"], ScanOptions(use_ai=True), ai=ai)
    users = next(f for f in r.findings if f.check_id == "wp.users_rest")
    assert users.severity == Severity.MEDIUM  # l'IA dice "alta" ma la gravità non cambia
    assert {n.purpose for n in users.ai_notes} >= {"explanation"}
    assert r.executive_summary_ai is True and r.model_used == "qwen3.5:4b"
    assert r.stats["ai"]["valid"] > 0
    # i dati del sito arrivano al modello solo fra i delimitatori <dati>
    assert all("<dati>" in p for p in fake_ollama.prompts)


def test_risposte_ia_non_valide_scartate(mock_sites, fake_ollama):
    fake_ollama.default = '{"risposta": "non rispetto lo schema"}'
    ai = _assistant(fake_ollama, retries=1)
    r = _scan(mock_sites["wp-vuln"], ScanOptions(use_ai=True), ai=ai)
    assert all(not f.ai_notes for f in r.findings)
    assert r.executive_summary_ai is False and r.executive_summary
    assert r.stats["ai"]["invalid"] > 0 and r.stats["ai"]["valid"] == 0


def test_assistente_ritenta_e_registra_i_tentativi(fake_ollama):
    from wpsec.core.models import Finding, FindingKind
    fake_ollama.responses = ["testo senza json", 500,
                             '{"spiegazione": "Spiegazione valida e abbastanza lunga.", "priorita": "Bassa"}']
    ai = _assistant(fake_ollama, retries=2)
    f = Finding(check_id="wp.xmlrpc", title="XML-RPC", category="wordpress",
                kind=FindingKind.MISCONFIGURATION, status=S.CONFIRMED, summary="metodi esposti")
    note = ai.explain(f)
    assert note is not None and note.attempts == 3 and note.suggested_priority == "bassa"


def test_ollama_spento_disattiva_l_assistente(unused_port):
    from wpsec.core.models import Finding, FindingKind
    ai = OllamaAssistant(OllamaClient(f"http://127.0.0.1:{unused_port}", timeout=2), "m", FAST)
    f = Finding(check_id="wp.xmlrpc", title="XML-RPC", category="wordpress",
                kind=FindingKind.MISCONFIGURATION, status=S.CONFIRMED)
    assert ai.explain(f) is None and ai.disabled_reason
    calls = ai.stats["calls"]
    assert ai.explain(f) is None and ai.stats["calls"] == calls  # nessun nuovo tentativo


def test_pianificatore_ia_con_azione_inventata(mock_sites, fake_ollama):
    fake_ollama.default = '{"azione": "brute_force_login", "motivo": "prova"}'
    ai = _assistant(fake_ollama, retries=0)
    r = _scan(mock_sites["wp-vuln"], ScanOptions(use_ai=True, planner="llm"), ai=ai)
    assert r.stats["planner"]["fallback"] is True
    assert {k: v for k, v in _status(r).items() if k in WP_CHECKS} == EXPECTED["wp-vuln"]


# ------------------------------------------------------------ archivio, report, confronto

def test_scansione_archiviata_riportata_e_confrontata(mock_sites, tmp_path):
    from wpsec.comparison.compare import Outcome, compare
    from wpsec.database.store import Store
    from wpsec.reports import render
    store = Store(tmp_path / "wpsec.sqlite3")
    tricky, vuln = _scan(mock_sites["wp-tricky"]), _scan(mock_sites["wp-vuln"])
    for r in (tricky, vuln):
        store.save_scan(r)
    md = render(store.get_scan(tricky.id), "md").decode()
    assert "Da verificare manualmente" in md and "falsi positivi" in md
    assert render(vuln, "pdf").startswith(b"%PDF")
    # stesso sito scansionato due volte: nulla di risolto, nulla di nuovo
    again = _scan(mock_sites["wp-vuln"])
    c = compare(vuln, again)
    assert c.counts()["resolved"] == 0 and c.counts()["new"] == 0
    assert any(r.outcome == Outcome.STILL_OPEN for r in c.rows)


def test_versione_nel_feed_con_permalink_semplici():
    """WordPress reale con permalink semplici: /feed/ 404, la versione è in ?feed=rss2
    (lacuna trovata sul laboratorio Docker il 17/11/2026)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/":
                code, body = 200, '<html><head><link rel="https://api.w.org/"></head><body></body></html>'
            elif self.path == "/?feed=rss2":
                code, body = 200, ("<rss><channel><generator>https://wordpress.org/?v=6.9.4"
                                   "</generator></channel></rss>")
            else:
                code, body = 404, "non trovato"
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            self.do_GET()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = _scan(f"http://127.0.0.1:{srv.server_address[1]}")
        v = next(f for f in r.findings if f.check_id == "wp.version_disclosure")
        assert v.status == S.CONFIRMED and v.details["version"] == "6.9.4"
        assert v.details["sources"] == {"feed": "6.9.4"}
    finally:
        srv.shutdown()
