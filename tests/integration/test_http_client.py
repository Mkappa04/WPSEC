"""Test del client HTTP con perimetro, contro i siti simulati (loopback).

Verifica le garanzie applicate dal CODICE: perimetro, SSRF, cache, redirect
controllati, budget e proxy. Nessuna rete esterna.
"""

from datetime import timedelta

import pytest

from tests.helpers import FAST, lab_auth, make_client
from wpsec.core.models import Authorization, AuthorizationKind, Origin, now_utc
from wpsec.scanner.http_client import (BudgetExceeded, ProxyConfig, ScopedHttpClient, ScopeError,
                                       ip_block_reason, mask_cookie)


# ------------------------------------------------------------ perimetro e sonde

def test_probe_home_ok(mock_sites):
    client = make_client(mock_sites["wp-vuln"])
    r = client.probe("home")
    assert r.ok and r.status == 200
    assert "home" in r.body
    assert r.evidence is not None and r.evidence.body_sha256


def test_probe_users_rest_esposti(mock_sites):
    r = make_client(mock_sites["wp-vuln"]).probe("wp_users_rest")
    assert r.status == 200 and '"slug":"admin"' in r.body


def test_probe_users_rest_protetti(mock_sites):
    r = make_client(mock_sites["wp-hard"]).probe("wp_users_rest")
    assert r.status == 401


def test_client_fuori_perimetro_in_costruzione(mock_sites):
    auth = lab_auth(mock_sites["wp-vuln"])  # scope = solo wp-vuln
    altro = Origin.from_url(mock_sites["wp-hard"])
    with pytest.raises(ScopeError):
        ScopedHttpClient(auth, altro, FAST)


# ------------------------------------------------------------ cache

def test_cache_evita_richiesta_doppia(mock_sites):
    client = make_client(mock_sites["wp-vuln"])
    client.probe("home")
    r2 = client.probe("home")
    assert client.stats["cache_hits"] == 1
    assert client.stats["requests"] == 1
    assert r2.evidence.from_cache is True


def test_fresh_ignora_cache(mock_sites):
    client = make_client(mock_sites["wp-vuln"])
    client.probe("home")
    client.probe("home", fresh=True)
    assert client.stats["requests"] == 2
    assert client.stats["cache_hits"] == 0


# ------------------------------------------------------------ redirect controllati

def test_redirect_autore_seguito_nel_perimetro(mock_sites):
    r = make_client(mock_sites["wp-vuln"]).probe("wp_author_1")
    assert r.status == 200
    assert any("/author/admin/" in u for u in r.redirect_chain)
    assert "archivio autore" in r.body


def test_xmlrpc_post_non_cacheable(mock_sites):
    client = make_client(mock_sites["wp-vuln"])
    client.probe("wp_xmlrpc")
    client.probe("wp_xmlrpc")
    assert client.stats["requests"] == 2  # POST non in cache


# ------------------------------------------------------------ budget

def test_budget_esaurito(mock_sites):
    settings = FAST.__class__(min_interval=0, request_timeout=5, max_requests=2)
    client = make_client(mock_sites["wp-vuln"], settings=settings)
    client.probe("home")
    client.probe("robots")
    r = client.probe("wp_json_root")
    assert not r.ok and "budget" in r.error.lower()


# ------------------------------------------------------------ SSRF / IP non pubblici

def test_ssrf_privato_vietato_senza_autorizzazione_lab():
    assert ip_block_reason("127.0.0.1", allow_private=False) is not None
    assert ip_block_reason("127.0.0.1", allow_private=True) is None
    assert ip_block_reason("10.0.0.5", allow_private=False) is not None


def test_ssrf_link_local_sempre_vietato():
    # 169.254.169.254 = metadati cloud: vietato anche con autorizzazione di laboratorio
    assert ip_block_reason("169.254.169.254", allow_private=True) is not None


def test_ssrf_blocca_rebinding_verso_link_local(mock_sites):
    """Anche un host del perimetro che risolve all'IP dei metadati cloud viene bloccato
    (il blocco avviene prima della connessione: difesa dal DNS rebinding)."""
    url = mock_sites["wp-vuln"]
    client = make_client(url, resolver=lambda h, p: ["169.254.169.254"])
    r = client.probe("home")
    assert not r.ok and r.scope_blocked
    assert client.stats["requests"] == 0  # bloccato prima di inviare


# ------------------------------------------------------------ ProxyConfig

def test_proxyconfig_parse_valido_e_invalido():
    p = ProxyConfig.parse("127.0.0.1:8080")
    assert p.host == "127.0.0.1" and p.port == 8080
    assert "TLS non verificato" in p.label
    with pytest.raises(ValueError):
        ProxyConfig.parse("127.0.0.1")           # manca porta
    with pytest.raises(ValueError):
        ProxyConfig.parse("8.8.8.8:8080")        # proxy non locale


# ------------------------------------------------------------ minimizzazione

def test_mask_cookie_nasconde_valore():
    assert mask_cookie("sess=abc123; Path=/; HttpOnly") == "sess=***; Path=/; HttpOnly"
    assert mask_cookie("token=xyz") == "token=***"
