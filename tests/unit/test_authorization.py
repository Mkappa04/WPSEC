"""Regole di creazione delle autorizzazioni."""

from datetime import timedelta

import pytest

from wpsec.core.authorization import (AuthorizationError, AuthorizationRequest,
                                      create_authorization, is_loopback_host)
from wpsec.core.models import AuthorizationKind, Origin, now_utc

BASE = dict(authorizer_name="Mario Rossi", authorizer_role="Titolare", operator="Studente")


def _req(**kw):
    return AuthorizationRequest(**{**BASE, **kw})


def test_sito_reale_valido():
    a = create_authorization(_req(target_url="https://www.sito.it/percorso",
                                  extra_scope=["https://sito.it"], document_ref="Lettera 10/11"))
    assert a.kind == AuthorizationKind.ENGAGEMENT
    assert a.scope == [Origin.from_url("https://www.sito.it"), Origin.from_url("https://sito.it")]
    assert not a.allow_private_addresses and not a.allow_active_checks
    assert a.is_valid_at()[0]


def test_sito_reale_richiede_documento():
    with pytest.raises(AuthorizationError, match="documento"):
        create_authorization(_req(target_url="https://www.sito.it"))


def test_sito_reale_niente_scansione_attiva():
    with pytest.raises(AuthorizationError, match="laboratorio"):
        create_authorization(_req(target_url="https://www.sito.it", document_ref="x",
                                  allow_active_checks=True))


def test_sito_reale_niente_loopback():
    with pytest.raises(AuthorizationError, match="laboratorio"):
        create_authorization(_req(target_url="http://127.0.0.1:8081", document_ref="x"))


def test_sito_reale_durata_massima():
    with pytest.raises(AuthorizationError, match="durata"):
        create_authorization(_req(target_url="https://www.sito.it", document_ref="x", days=200))


def test_laboratorio_solo_loopback():
    a = create_authorization(_req(kind="lab", target_url="http://127.0.0.1:8081",
                                  extra_scope=["http://localhost:8082"], allow_active_checks=True))
    assert a.kind == AuthorizationKind.LAB and a.allow_private_addresses and a.allow_active_checks
    with pytest.raises(AuthorizationError, match="loopback"):
        create_authorization(_req(kind="lab", target_url="http://192.168.1.10"))
    with pytest.raises(AuthorizationError, match="loopback"):
        create_authorization(_req(kind="lab", target_url="http://127.0.0.1",
                                  extra_scope=["https://www.sito.it"]))


def test_date_incoerenti():
    now = now_utc()
    with pytest.raises(AuthorizationError, match="fine"):
        create_authorization(_req(kind="lab", target_url="http://127.0.0.1",
                                  valid_from=now, valid_until=now - timedelta(hours=1)))


def test_hash_del_documento():
    with pytest.raises(AuthorizationError, match="SHA-256"):
        create_authorization(_req(target_url="https://www.sito.it", document_ref="x",
                                  document_sha256="zz"))
    a = create_authorization(_req(target_url="https://www.sito.it", document_ref="x",
                                  document_sha256="AB" * 32))
    assert a.document_sha256 == "ab" * 32


@pytest.mark.parametrize("url", ["ftp://sito.it", "https://user:pw@sito.it", "https://"])
def test_url_non_validi(url):
    with pytest.raises(AuthorizationError):
        create_authorization(_req(target_url=url + "/xxxxxxxx", document_ref="x"))


def test_loopback():
    assert is_loopback_host("127.0.0.5") and is_loopback_host("::1") and is_loopback_host("localhost")
    assert not is_loopback_host("10.0.0.1") and not is_loopback_host("sito.it")
