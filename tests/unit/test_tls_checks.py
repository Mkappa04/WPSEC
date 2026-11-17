"""Test delle funzioni pure di valutazione TLS (certificato e protocollo)."""

from wpsec.core.models import FindingStatus
from wpsec.scanner.tls_checks import TLSInfo, certificate_outcome, protocol_outcome

S = FindingStatus


def test_certificato_valido():
    info = TLSInfo(verified=True, issuer="Let's Encrypt", not_after="Dec 31 2027", days_left=200)
    assert certificate_outcome(info).status is S.NOT_DETECTED


def test_certificato_non_valido():
    info = TLSInfo(verified=False, verify_error="hostname mismatch")
    out = certificate_outcome(info)
    assert out.status is S.CANDIDATE
    assert out.details["problem"] == "invalid"


def test_certificato_in_scadenza():
    info = TLSInfo(verified=True, days_left=10, not_after="xxx")
    out = certificate_outcome(info)
    assert out.status is S.CANDIDATE
    assert out.details["problem"] == "expiring"


def test_certificato_errore_handshake():
    assert certificate_outcome(TLSInfo(error="connection refused")).status is S.ERROR


def test_protocollo_obsoleto():
    assert protocol_outcome(TLSInfo(protocol="TLSv1")).status is S.CANDIDATE
    assert protocol_outcome(TLSInfo(protocol="TLSv1.1")).status is S.CANDIDATE


def test_protocollo_moderno():
    assert protocol_outcome(TLSInfo(protocol="TLSv1.3", cipher="X")).status is S.NOT_DETECTED


def test_protocollo_non_determinato():
    assert protocol_outcome(TLSInfo(protocol="")).status is S.INCONCLUSIVE
