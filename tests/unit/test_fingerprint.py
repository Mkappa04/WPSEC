"""Test delle funzioni pure di fingerprinting (WAF, WordPress, tecnologie, robots)."""

from wpsec.scanner import fingerprint as fp


# ------------------------------------------------------------ WAF

def test_detect_waf_cloudflare_e_sucuri():
    assert fp.detect_waf({"cf-ray": "abc"}) == ["Cloudflare"]
    assert fp.detect_waf({"server": "sucuri/cloudproxy"}) == ["Sucuri"]
    assert fp.detect_waf({}) == []


def test_detect_waf_niente_duplicati():
    found = fp.detect_waf({"server": "cloudflare", "cf-ray": "abc"})
    assert found == ["Cloudflare"]


def test_looks_like_waf_block():
    assert fp.looks_like_waf_block(503, {}, "", []) is True
    assert fp.looks_like_waf_block(429, {}, "", []) is True
    # 403 è un blocco solo se c'è un segnale di WAF
    assert fp.looks_like_waf_block(403, {"cf-ray": "x"}, "", []) is True
    assert fp.looks_like_waf_block(403, {}, "Attention Required! Cloudflare", []) is True
    assert fp.looks_like_waf_block(403, {}, "Forbidden", []) is False
    assert fp.looks_like_waf_block(200, {}, "", ["Cloudflare"]) is False


# ------------------------------------------------------------ WordPress

def test_detect_wordpress_alta_confidenza():
    body = ('<meta name="generator" content="WordPress 6.8">'
            '<link rel="https://api.w.org/" href="/wp-json/">')
    rilevato, conf, ind = fp.detect_wordpress(200, {}, body, 200,
                                              '{"namespaces":["wp/v2"]}')
    assert rilevato is True
    assert conf == "high"
    assert len(ind) >= 2


def test_detect_wordpress_media_confidenza():
    rilevato, conf, ind = fp.detect_wordpress(200, {}, "<link href='/wp-content/x'>", 404, "")
    assert rilevato is True and conf == "medium" and len(ind) == 1


def test_detect_wordpress_assente():
    rilevato, conf, ind = fp.detect_wordpress(200, {}, "<html>statico</html>", 404, "")
    assert rilevato is False and ind == []


# ------------------------------------------------------------ tecnologie

def test_detect_technologies_estrae_php_tema_plugin():
    headers = {"server": "Apache", "x-powered-by": "PHP/8.1.2"}
    body = ('/wp-content/themes/twentytwentyfour/style.css '
            '/wp-content/plugins/akismet/a.js /wp-content/plugins/jetpack/b.js')
    tech = fp.detect_technologies(headers, body)
    assert tech["php"] == "8.1.2"
    assert tech["wp_theme"] == "twentytwentyfour"
    assert "akismet" in tech["wp_plugins_visibili"]
    assert "jetpack" in tech["wp_plugins_visibili"]


# ------------------------------------------------------------ robots

def test_robots_paths_estrae_percorsi():
    body = "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n"
    assert fp.robots_paths(200, body) == ["/wp-admin/", "/wp-admin/admin-ajax.php"]


def test_robots_paths_html_o_non_200():
    assert fp.robots_paths(200, "<html>404</html>") == []
    assert fp.robots_paths(404, "Disallow: /x") == []
