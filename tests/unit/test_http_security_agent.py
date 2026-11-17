"""HTTP Security Agent sui rami HTTPS (redirect, TLS, cookie) con risposte finte, senza rete."""

from tests.helpers import lab_auth, make_ctx
from wpsec.agents.evidence_agent import EvidenceValidationAgent
from wpsec.agents.http_security_agent import HttpSecurityAgent
from wpsec.core.models import Evidence, FindingStatus
from wpsec.scanner.http_client import HttpResponse
from wpsec.scanner.tls_checks import TLSInfo

S = FindingStatus
HTTPS = "https://sito.test"
GOOD_HEADERS = {"strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
                "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
                "permissions-policy": "camera=()"}


def _resp(ctx, probe_id, status=200, headers=None, cookies=(), body="", error=None):
    r = HttpResponse(probe_id, "GET", HTTPS + "/", status=status, headers=dict(headers or {}),
                     set_cookies=list(cookies), body=body, error=error)
    r.evidence = Evidence(probe_id=probe_id, method="GET", url=r.url, status_code=status, error=error)
    ctx.register_evidence(r.evidence)
    return r


def _ctx(http_in_scope=True, home_headers=GOOD_HEADERS, cookies=(), redirect=None, tls=None):
    urls = [HTTPS] + (["http://sito.test"] if http_in_scope else [])
    ctx = make_ctx(HTTPS, auth=lab_auth(*urls))
    ctx.shared["home"] = _resp(ctx, "home", headers=home_headers, cookies=cookies)
    ctx.shared["tls"] = tls or TLSInfo(protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
                                       verified=True, issuer="Let's Encrypt",
                                       not_after="Jan  1 00:00:00 2027 GMT", days_left=200)
    calls = []

    def fake_probe(probe_id, fresh=False):
        calls.append((probe_id, fresh))
        assert probe_id == "http_redirect"
        return _resp(ctx, probe_id, **(redirect or {"status": 301,
                                                    "headers": {"location": HTTPS + "/"}}))
    ctx.client.probe = fake_probe
    ctx.calls = calls
    return ctx


def _run(ctx):
    HttpSecurityAgent().run(ctx)
    return {f.check_id: f for f in ctx.findings}


def test_sito_https_ben_configurato():
    f = _run(_ctx())
    assert all(f[k].status == S.NOT_DETECTED for k in
               ("http.header.hsts", "http.header.csp", "http.header.xfo", "http.https_redirect",
                "tls.certificate", "tls.protocol"))
    assert f["tls.https"].status == S.INFO
    assert f["http.cookies"].status == S.NOT_APPLICABLE


def test_tls_ha_un_evidenza_registrata_e_confermabile():
    ctx = _ctx(tls=TLSInfo(protocol="TLSv1.2", verified=False,
                           verify_error="self-signed certificate"))
    f = _run(ctx)
    cert = f["tls.certificate"]
    assert cert.status == S.CANDIDATE
    ev = ctx.evidence(cert.evidence_ids[0])
    assert ev.method == "TLS" and "verificato=no" in ev.excerpt
    EvidenceValidationAgent().run(ctx)
    assert cert.status == S.CONFIRMED


def test_handshake_fallito_e_errore():
    ctx = _ctx()
    del ctx.shared["tls"]
    ctx.shared["tls_error"] = "ConnectionResetError"
    f = _run(ctx)
    assert f["tls.certificate"].status == S.ERROR
    assert f["tls.protocol"].status == S.INCONCLUSIVE


def test_http_senza_redirect_candidato():
    f = _run(_ctx(redirect={"status": 200}))
    assert f["http.https_redirect"].status == S.CANDIDATE


def test_redirect_verso_http_candidato():
    f = _run(_ctx(redirect={"status": 302, "headers": {"location": "http://altro.test/"}}))
    assert f["http.https_redirect"].status == S.CANDIDATE


def test_porta_80_chiusa_non_e_un_problema():
    f = _run(_ctx(redirect={"status": 0, "error": "errore di rete: ConnectionRefusedError: "
                                                  "[Errno 111] Connection refused"}))
    assert f["http.https_redirect"].status == S.NOT_DETECTED


def test_origine_http_fuori_perimetro_non_contattata():
    ctx = _ctx(http_in_scope=False)
    f = _run(ctx)
    assert f["http.https_redirect"].status == S.NOT_APPLICABLE
    assert f["http.https_redirect"].details["out_of_scope"] is True
    assert ctx.calls == []


def test_errore_di_rete_sul_redirect_ricontrollabile():
    ctx = _ctx(redirect={"status": 0, "error": "timeout dopo 5s"})
    f = _run(ctx)
    assert f["http.https_redirect"].status == S.ERROR
    assert "http.https_redirect" in ctx.rechecks


def test_cookie_senza_attributi():
    f = _run(_ctx(cookies=["sess=abc; Path=/", "ok=1; Secure; HttpOnly; SameSite=Lax"]))
    c = f["http.cookies"]
    assert c.status == S.CANDIDATE
    assert c.details["cookies"] == {"sess": ["secure", "httponly", "samesite"]}
    assert "abc" not in c.summary  # il valore del cookie non viene riportato


def test_header_mancanti_e_deboli():
    f = _run(_ctx(home_headers={"strict-transport-security": "max-age=300",
                                "x-powered-by": "PHP/8.1.2"}))
    assert f["http.header.hsts"].status == S.CANDIDATE and "debole" in f["http.header.hsts"].summary
    assert f["http.header.csp"].status == S.CANDIDATE
    assert f["http.info_disclosure"].status == S.CANDIDATE


def test_home_bloccata_annotata_sugli_header():
    ctx = _ctx(home_headers={})
    ctx.shared["home_blocked"] = True
    f = _run(ctx)
    assert f["http.header.csp"].details.get("waf_block") is True
    EvidenceValidationAgent().run(ctx)
    assert f["http.header.csp"].status == S.INCONCLUSIVE
