"""Test dei modelli dati: Origin, Authorization, transizioni di stato, conteggi."""

from datetime import timedelta

import pytest
from pydantic import ValidationError

from wpsec.core.models import (ALLOWED_TRANSITIONS, Authorization, AuthorizationKind, Confidence,
                               Evidence, Finding, FindingKind, FindingStatus, Origin, ScanOptions,
                               Severity, now_utc)

S = FindingStatus


# ------------------------------------------------------------ Origin

def test_origin_from_url_normalizza_host_e_porta_default():
    o = Origin.from_url("HTTP://Example.COM./path?x=1")
    assert o.scheme == "http" and o.host == "example.com" and o.port == 80
    assert Origin.from_url("https://x.it").port == 443


def test_origin_url_omette_porta_default_e_mantiene_esplicita():
    assert Origin.from_url("https://x.it").url == "https://x.it"
    assert Origin.from_url("http://x.it:8080").url == "http://x.it:8080"


def test_origin_rifiuta_schema_credenziali_e_host_mancante():
    with pytest.raises(ValueError):
        Origin.from_url("ftp://x.it")
    with pytest.raises(ValueError):
        Origin.from_url("http://user:pass@x.it")
    with pytest.raises(ValueError):
        Origin.from_url("http:///solopath")


def test_origin_frozen_e_uguaglianza():
    a = Origin.from_url("https://x.it")
    b = Origin.from_url("https://X.it:443")
    assert a == b
    with pytest.raises(ValidationError):
        a.port = 8443  # frozen


# ------------------------------------------------------------ Authorization

def _auth(**kw):
    base = dict(kind=AuthorizationKind.LAB, target_url="http://127.0.0.1:9",
                scope=[Origin.from_url("http://127.0.0.1:9")],
                authorizer_name="Lab", authorizer_role="Tutor", operator="Studente",
                valid_from=now_utc() - timedelta(hours=1),
                valid_until=now_utc() + timedelta(hours=1))
    base.update(kw)
    return Authorization(**base)


def test_authorization_validita_temporale():
    assert _auth().is_valid_at()[0] is True
    assert _auth(revoked=True).is_valid_at()[0] is False
    assert _auth(valid_from=now_utc() + timedelta(hours=1)).is_valid_at()[0] is False
    assert _auth(valid_until=now_utc() - timedelta(minutes=1)).is_valid_at()[0] is False


def test_authorization_covers_solo_origini_in_scope():
    auth = _auth(scope=[Origin.from_url("http://127.0.0.1:9")])
    assert auth.covers(Origin.from_url("http://127.0.0.1:9")) is True
    assert auth.covers(Origin.from_url("http://127.0.0.1:10")) is False
    assert auth.covers(Origin.from_url("https://127.0.0.1:9")) is False  # schema diverso


def test_authorization_rifiuta_autorizzatore_corto():
    with pytest.raises(ValidationError):
        _auth(authorizer_name="x")


# ------------------------------------------------------------ Transizioni

def test_nessun_percorso_verso_confirmed_da_not_detected():
    assert FindingStatus.CONFIRMED not in ALLOWED_TRANSITIONS[FindingStatus.NOT_DETECTED]
    assert FindingStatus.CONFIRMED in ALLOWED_TRANSITIONS[FindingStatus.CANDIDATE]


def test_stati_finali_senza_uscite():
    for finale in (S.CONFIRMED, S.FALSE_POSITIVE, S.NOT_PRESENT, S.NOT_APPLICABLE, S.INFO):
        assert ALLOWED_TRANSITIONS[finale] == set()


# ------------------------------------------------------------ Severity / conteggi

def test_severity_rank_ordinato():
    assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.INFO.rank
    assert Severity.MEDIUM.label_it == "Media"


def _scan_result():
    from wpsec.core.models import ScanResult
    return ScanResult(platform_version="4.0.0", catalog_version="test", target="http://127.0.0.1:9",
                      host="127.0.0.1", authorization=_auth(), options=ScanOptions())


def test_scanresult_counts_e_severity_counts():
    res = _scan_result()
    res.findings = [
        Finding(check_id="a", title="A", category="http", kind=FindingKind.MISCONFIGURATION,
                status=S.CONFIRMED, severity=Severity.HIGH),
        Finding(check_id="b", title="B", category="http", kind=FindingKind.MISCONFIGURATION,
                status=S.CONFIRMED, severity=Severity.HIGH),
        Finding(check_id="c", title="C", category="wordpress", kind=FindingKind.INFORMATIONAL,
                status=S.NOT_PRESENT),
    ]
    assert res.counts() == {"confirmed": 2, "not_present": 1}
    assert res.severity_counts()["high"] == 2
    assert res.severity_counts()["low"] == 0


def test_evidence_default_timestamp_e_id():
    ev = Evidence(probe_id="home", method="GET", url="http://x/")
    assert ev.id.startswith("ev-")
    assert ev.body_length == 0


def test_scan_options_label_pattern():
    ScanOptions(label="scan-01")
    with pytest.raises(ValidationError):
        ScanOptions(label="bad/label!")
