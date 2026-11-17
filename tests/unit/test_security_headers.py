"""Test delle funzioni pure sugli header di sicurezza, disclosure e cookie."""

from wpsec.scanner import security_headers as sh


def _by_key(assessments):
    return {a.key: a for a in assessments}


def test_header_tutti_presenti_ok():
    headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
        "x-frame-options": "SAMEORIGIN",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    res = _by_key(sh.analyze_security_headers(headers, "https"))
    assert all(a.status == "ok" for a in res.values()), {k: a.status for k, a in res.items()}


def test_header_tutti_mancanti():
    res = _by_key(sh.analyze_security_headers({}, "https"))
    assert res["hsts"].status == "missing"
    assert res["csp"].status == "missing"
    assert res["xfo"].status == "missing"
    assert res["xcto"].status == "missing"


def test_hsts_non_applicabile_su_http():
    res = _by_key(sh.analyze_security_headers({"strict-transport-security": "max-age=1"}, "http"))
    assert res["hsts"].status == "not_applicable"


def test_hsts_debole_max_age_basso():
    res = _by_key(sh.analyze_security_headers({"strict-transport-security": "max-age=300"}, "https"))
    assert res["hsts"].status == "weak"
    assert any("180" in i for i in res["hsts"].issues)


def test_csp_unsafe_inline_debole():
    headers = {"content-security-policy": "script-src 'self' 'unsafe-inline'"}
    res = _by_key(sh.analyze_security_headers(headers, "https"))
    assert res["csp"].status == "weak"
    assert any("unsafe-inline" in i for i in res["csp"].issues)


def test_csp_nonce_non_e_debole():
    headers = {"content-security-policy": "script-src 'self' 'unsafe-inline' 'nonce-abc'"}
    res = _by_key(sh.analyze_security_headers(headers, "https"))
    assert res["csp"].status == "ok"


def test_xfo_coperto_da_frame_ancestors():
    headers = {"content-security-policy": "frame-ancestors 'self'"}
    res = _by_key(sh.analyze_security_headers(headers, "https"))
    assert res["xfo"].status == "ok"
    assert any("frame-ancestors" in i for i in res["xfo"].issues)


def test_xcto_valore_sbagliato_debole():
    res = _by_key(sh.analyze_security_headers({"x-content-type-options": "sniff"}, "https"))
    assert res["xcto"].status == "weak"


def test_referrer_policy_debole_unsafe_url():
    res = _by_key(sh.analyze_security_headers({"referrer-policy": "unsafe-url"}, "https"))
    assert res["referrer"].status == "weak"


def test_check_id_proprieta():
    a = sh.HeaderAssessment("hsts", "Strict-Transport-Security", "ok")
    assert a.check_id == "http.header.hsts"


# ------------------------------------------------------------ disclosure

def test_disclosure_server_con_versione():
    out = sh.disclosure_headers({"server": "Apache/2.4.57", "x-powered-by": "PHP/8.1.2"})
    assert out["server"] == "Apache/2.4.57"
    assert out["x-powered-by"] == "PHP/8.1.2"


def test_disclosure_server_senza_versione_ignorato():
    assert sh.disclosure_headers({"server": "nginx"}) == {}
    assert sh.disclosure_headers({"server": "cloudflare"}) == {}


# ------------------------------------------------------------ cookie

def test_analyze_cookies_attributi():
    c = sh.analyze_cookies(["sess=abc; Path=/; Secure; HttpOnly; SameSite=Lax"])[0]
    assert c.name == "sess"
    assert c.secure and c.httponly
    assert c.samesite == "lax"


def test_analyze_cookies_mancano_attributi():
    c = sh.analyze_cookies(["sess=abc; Path=/"])[0]
    assert not c.secure and not c.httponly
    assert c.samesite == ""
