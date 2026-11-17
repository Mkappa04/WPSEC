"""API FastAPI e protezioni dell'interfaccia locale (TestClient, siti simulati)."""

import time

import pytest
from fastapi.testclient import TestClient

from tests.helpers import FAST
from wpsec.database.store import Store
from wpsec.web.app import create_app

LAB = dict(kind="lab", authorizer_name="Laboratorio", authorizer_role="Tutor", operator="Studente")


@pytest.fixture
def client(tmp_path):
    settings = FAST.with_overrides(data_dir=tmp_path)
    app = create_app(settings, Store(settings.db_path), ai=None)
    with TestClient(app, base_url="http://127.0.0.1:8000") as c:
        yield c


def _auth(client, url):
    r = client.post("/api/authorizations", json={**LAB, "target_url": url})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _wait(client, scan_id, timeout=15):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        r = client.get(f"/api/scans/{scan_id}")
        if r.status_code == 200 and not r.json()["live"]:
            return r.json()
        time.sleep(0.1)
    raise AssertionError("scansione non terminata")


def test_flusso_completo(client, mock_sites):
    url = mock_sites["wp-tricky"]
    auth_id = _auth(client, url)
    r = client.post("/api/scans", json={"authorization_id": auth_id, "target_url": url,
                                        "options": {"use_ai": False, "label": "prima"}})
    assert r.status_code == 202
    scan = _wait(client, r.json()["id"])
    assert scan["status"] == "completed" and "trace" not in scan
    st = {f["check_id"]: f["status"] for f in scan["findings"]}
    assert st["wp.users_rest"] == "inconclusive" and st["wp.directory_listing"] == "false_positive"
    assert client.get(f"/api/scans/{scan['id']}?trace=true").json()["trace"]
    rows = client.get("/api/scans").json()
    assert rows[0]["id"] == scan["id"] and rows[0]["live"] is False

    # report in tutti i formati
    for fmt, ctype in (("html", "text/html"), ("md", "text/markdown"), ("json", "application/json"),
                       ("pdf", "application/pdf")):
        rep = client.get(f"/api/scans/{scan['id']}/report.{fmt}")
        assert rep.status_code == 200 and rep.headers["content-type"].startswith(ctype)
        assert "sandbox" in rep.headers["content-security-policy"]
    assert client.get(f"/api/scans/{scan['id']}/report.docx").status_code == 404
    assert client.get(f"/api/scans/{scan['id']}/report.json?anonymize=true").status_code == 400

    # seconda scansione e confronto
    r2 = client.post("/api/scans", json={"authorization_id": auth_id, "target_url": url,
                                         "options": {"use_ai": False, "label": "dopo"}})
    _wait(client, r2.json()["id"])
    c = client.get("/api/compare", params={"host": "127.0.0.1"}).json()
    assert c["counts"]["resolved"] == 0 and c["counts"]["new"] == 0
    md = client.get("/api/compare", params={"host": "127.0.0.1", "format": "md"})
    assert md.text.startswith("# Confronto")
    hist = client.get("/api/history", params={"host": "127.0.0.1", "check_id": "wp.users_rest"})
    assert [h["status"] for h in hist.json()] == ["inconclusive", "inconclusive"]

    # andamento nel tempo ed evidenze di un risultato
    tl = {i["check_id"]: i for i in client.get("/api/timeline", params={"host": "127.0.0.1"}).json()}
    assert tl["wp.version_disclosure"]["times_confirmed"] == 2
    fid = next(f["id"] for f in scan["findings"] if f["check_id"] == "wp.version_disclosure")
    det = client.get(f"/api/findings/{fid}/evidence").json()
    assert {e["probe_id"] for e in det["evidence"]} == {"wp_feed"}
    assert [h["to_status"] for h in det["status_history"]] == ["candidate", "confirmed"]

    # cancellazione
    assert client.delete(f"/api/scans/{scan['id']}").status_code == 204
    assert client.get(f"/api/scans/{scan['id']}").status_code == 404


def test_scansione_fuori_perimetro_rifiutata_subito(client, mock_sites):
    auth_id = _auth(client, mock_sites["wp-vuln"])
    r = client.post("/api/scans", json={"authorization_id": auth_id,
                                        "target_url": mock_sites["wp-hard"]})
    assert r.status_code == 400 and "perimetro" in r.json()["detail"]
    assert client.get("/api/scans").json() == []


def test_autorizzazione_revocata(client, mock_sites):
    url = mock_sites["wp-vuln"]
    auth_id = _auth(client, url)
    assert client.post(f"/api/authorizations/{auth_id}/revoke").json()["revoked"] is True
    r = client.post("/api/scans", json={"authorization_id": auth_id, "target_url": url})
    assert r.status_code == 400 and "revocata" in r.json()["detail"]
    assert client.get("/api/authorizations?only_valid=true").json() == []


def test_autorizzazione_inesistente(client):
    r = client.post("/api/scans", json={"authorization_id": "auth-nessuna",
                                        "target_url": "http://127.0.0.1:1"})
    assert r.status_code == 404


def test_autorizzazione_non_valida(client):
    r = client.post("/api/authorizations", json={**LAB, "target_url": "https://www.sito.it"})
    assert r.status_code == 400 and "loopback" in r.json()["detail"]
    r = client.post("/api/authorizations", json={"target_url": "https://www.sito.it"})
    assert r.status_code == 422


def test_limite_di_scansioni_contemporanee(client, mock_sites):
    url = mock_sites["wp-vuln"]
    auth_id = _auth(client, url)
    manager = client.app.state.manager
    gate = __import__("threading").Event()
    original = manager._on_update
    manager._on_update = lambda run, ctx: (original(run, ctx), gate.wait(5))
    body = {"authorization_id": auth_id, "target_url": url, "options": {"use_ai": False}}
    first = client.post("/api/scans", json=body).json()["id"]
    try:
        r = client.post("/api/scans", json=body)
        assert r.status_code == 429
        assert client.post(f"/api/scans/{first}/cancel").status_code == 200
    finally:
        gate.set()
    scan = _wait(client, first)
    assert scan["status"] == "cancelled"
    assert client.post(f"/api/scans/{first}/cancel").status_code == 409


# ------------------------------------------------------------ protezioni dell'interfaccia

def test_host_non_locale_rifiutato(client):
    r = client.get("/api/health", headers={"host": "attacker.example"})
    assert r.status_code == 400  # DNS rebinding


def test_origine_esterna_rifiutata(client, mock_sites):
    r = client.post("/api/authorizations", json={**LAB, "target_url": mock_sites["wp-vuln"]},
                    headers={"origin": "https://attacker.example"})
    assert r.status_code == 403
    assert client.get("/api/authorizations").json() == []


def test_corpo_non_json_rifiutato(client):
    r = client.post("/api/authorizations", content="target_url=x",
                    headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415


def test_header_di_sicurezza_e_dashboard(client):
    r = client.get("/")
    assert r.status_code == 200 and "app.js" in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp.split("style-src")[0]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/static/app.js").status_code == 200
    assert "innerHTML" not in client.get("/static/app.js").text
    assert client.get("/api/docs").status_code == 404  # nessuna pagina con script da CDN


def test_health_e_catalogo(client):
    h = client.get("/api/health").json()
    assert h["running"] == 0 and h["version"]
    cat = client.get("/api/catalog").json()
    assert any(c["check_id"] == "wp.users_rest" and c["cwe"] == "CWE-200" for c in cat)


def test_scansioni_interrotte_all_avvio(tmp_path):
    from tests.helpers import lab_auth
    from wpsec import __version__
    from wpsec.core.models import ScanOptions, ScanResult
    from wpsec.knowledge.catalog import CATALOG_VERSION
    settings = FAST.with_overrides(data_dir=tmp_path)
    store = Store(settings.db_path)
    url = "http://127.0.0.1:9"
    r = ScanResult(platform_version=__version__, catalog_version=CATALOG_VERSION, target=url,
                   host="127.0.0.1", authorization=lab_auth(url), options=ScanOptions(),
                   status="running")
    store.save_scan(r)
    with TestClient(create_app(settings, store, ai=None), base_url="http://127.0.0.1:8000") as c:
        assert c.get(f"/api/scans/{r.id}").json()["status"] == "failed"
