"""Test delle funzioni pure di analisi dei controlli WordPress (nessuna rete)."""

from wpsec.core.models import Confidence, FindingStatus
from wpsec.scanner import wordpress_checks as wc

S = FindingStatus


# ------------------------------------------------------------ utenti REST

def test_parse_rest_users_lista_valida():
    body = '[{"id":1,"name":"admin","slug":"admin"},{"id":2,"slug":"editor"}]'
    users = wc.parse_rest_users(200, body)
    assert users == [{"id": 1, "slug": "admin"}, {"id": 2, "slug": "editor"}]


def test_parse_rest_users_scarta_oggetti_senza_id_o_slug():
    assert wc.parse_rest_users(200, '[{"name":"x"},{"id":5}]') is None


def test_parse_rest_users_non_json_o_non_lista():
    assert wc.parse_rest_users(200, "non-json") is None
    assert wc.parse_rest_users(200, '{"code":"rest_cannot_access"}') is None
    assert wc.parse_rest_users(401, "[]") is None


def test_users_outcome_candidate_con_redazione():
    body = '[{"id":1,"name":"admin","slug":"administrator"}]'
    out = wc.users_outcome(200, body, "/wp-json/wp/v2/users", redact=True)
    assert out.status is S.CANDIDATE
    assert out.confidence is Confidence.HIGH
    assert out.details["count"] == 1
    assert "administrator" not in out.summary  # username mascherato
    assert out.summary.count("a") >= 1


def test_users_outcome_senza_redazione_mostra_slug():
    body = '[{"id":1,"slug":"administrator"}]'
    out = wc.users_outcome(200, body, "/x", redact=False)
    assert "administrator" in out.summary


def test_users_outcome_bloccato_e_inconcludente():
    assert wc.users_outcome(401, "", "/x", redact=True).status is S.NOT_DETECTED
    assert wc.users_outcome(200, "{}", "/x", redact=True).status is S.NOT_DETECTED
    assert wc.users_outcome(500, "", "/x", redact=True).status is S.INCONCLUSIVE


# ------------------------------------------------------------ autori

def test_author_from_urls_ignora_id_numerici():
    assert wc.author_from_urls(["http://x/author/1/"]) is None
    assert wc.author_from_urls(["http://x/author/admin/"]) == "admin"


def test_author_from_body_classe_body():
    body = '<body class="archive author author-pippo">'
    assert wc.author_from_body(body) == "pippo"
    assert wc.author_from_body('<body class="home">') is None


def test_author_outcome_da_redirect():
    out = wc.author_outcome(301, "", ["/author/admin/"], redact=False)
    assert out.status is S.CANDIDATE
    assert "admin" in out.summary and "redirect" in out.summary


def test_author_outcome_niente_username():
    out = wc.author_outcome(404, "", [], redact=True)
    assert out.status is S.NOT_DETECTED


# ------------------------------------------------------------ XML-RPC

def test_xmlrpc_outcome_metodi_esposti_e_multicall():
    body = ("<methodResponse><string>system.multicall</string>"
            "<string>wp.getUsersBlogs</string></methodResponse>")
    out = wc.xmlrpc_outcome(200, body)
    assert out.status is S.CANDIDATE
    assert out.details["multicall"] is True
    assert out.details["methods"] == 2


def test_xmlrpc_outcome_fault_non_esposto():
    out = wc.xmlrpc_outcome(200, "<methodResponse><fault>...</fault></methodResponse>")
    assert out.status is S.NOT_DETECTED
    assert out.details.get("fault") is True


def test_xmlrpc_outcome_bloccato():
    assert wc.xmlrpc_outcome(403, "Forbidden").status is S.NOT_DETECTED
    assert wc.xmlrpc_outcome(405, "POST only").status is S.NOT_DETECTED


# ------------------------------------------------------------ versione

def test_version_from_meta_ordine_attributi():
    assert wc.version_from_meta('<meta content="WordPress 6.8.1" name="generator">') == "6.8.1"
    assert wc.version_from_meta('<meta name="generator" content="WordPress 6.8">') == "6.8"
    assert wc.version_from_meta('<meta name="generator" content="Joomla 4">') is None


def test_version_from_feed_e_readme_e_assets():
    assert wc.version_from_feed(
        "<generator>https://wordpress.org/?v=6.8.1</generator>") == "6.8.1"
    assert wc.version_from_readme("<br />Version 6.7.2") == "6.7.2"
    assert wc.version_from_assets('<script src="/wp-includes/js/x.js?ver=6.8.1">') == "6.8.1"


def test_version_outcome_forte_vs_debole():
    forte = wc.version_outcome({"meta": "6.8.1", "feed": None, "readme": None, "assets": None})
    assert forte.status is S.CANDIDATE and forte.confidence is Confidence.HIGH
    debole = wc.version_outcome({"meta": None, "feed": None, "readme": None, "assets": "6.8.1"})
    assert debole.status is S.CANDIDATE and debole.confidence is Confidence.MEDIUM
    assente = wc.version_outcome({"meta": None, "feed": None, "readme": None, "assets": None})
    assert assente.status is S.NOT_DETECTED


def test_version_outcome_segnala_conflitto():
    out = wc.version_outcome({"meta": "6.8.1", "feed": "6.7.0", "readme": None, "assets": None})
    assert out.details["conflict"] is True


# ------------------------------------------------------------ directory listing

def test_directory_listing_firma_forte():
    out = wc.directory_listing_outcome(200, "<h1>Index of /wp-content/uploads</h1>")
    assert out.status is S.CANDIDATE and out.confidence is Confidence.HIGH
    assert out.details["signature"] == "strong"


def test_directory_listing_falso_positivo_pagina_wp():
    """La parola 'Index of' in una pagina del tema non è un listing (confidenza bassa)."""
    body = '<article>cos\'è Index of /?</article><script src="/wp-content/themes/t/a.js">'
    out = wc.directory_listing_outcome(200, body)
    assert out.status is S.CANDIDATE and out.confidence is Confidence.LOW
    assert out.details["wp_page_markers"] is True
    assert out.details["signature"] == "weak"


def test_directory_listing_protetto():
    assert wc.directory_listing_outcome(403, "Forbidden").status is S.NOT_DETECTED


# ------------------------------------------------------------ debug.log

def test_debug_log_outcome_pubblico():
    out = wc.debug_log_outcome(200, "[15-Nov-2026] PHP Warning: foo in bar\n")
    assert out.status is S.CANDIDATE and out.confidence is Confidence.HIGH


def test_debug_log_outcome_non_log():
    assert wc.debug_log_outcome(200, "<html>sito</html>").status is S.NOT_DETECTED
    assert wc.debug_log_outcome(404, "").status is S.NOT_DETECTED


# ------------------------------------------------------------ login

def test_login_page_outcome_e_sempre_info():
    assert wc.login_page_outcome(200, '<input name="log">').status is S.INFO
    assert wc.login_page_outcome(403, "").status is S.INFO


def test_redact_username():
    assert wc.redact_username("admin") == "a***n"
    assert wc.redact_username("ab") == "**"
    assert wc.redact_username("a") == "*"
