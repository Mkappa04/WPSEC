"""Controlli TLS non invasivi: un solo handshake verso l'IP già verificato.

La connessione TLS è sempre DIRETTA (mai attraverso Burp): passando dal proxy si
vedrebbe il certificato di Burp e non quello del sito.

Limite dichiarato: si registra la versione negoziata (la migliore offerta dal server),
non si provano versioni obsolete. OpenSSL 3 rifiuta TLS 1.0/1.1 lato client, quindi
quella verifica non sarebbe affidabile con la sola libreria standard.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field

from wpsec.core.models import Confidence, FindingStatus
from wpsec.scanner.wordpress_checks import CheckOutcome

EXPIRY_WARNING_DAYS = 30


@dataclass
class TLSInfo:
    protocol: str = ""
    cipher: str = ""
    verified: bool = False
    verify_error: str = ""
    subject_cn: str = ""
    issuer: str = ""
    san: list[str] = field(default_factory=list)
    not_after: str = ""
    days_left: int | None = None
    error: str = ""


def _name(rdns) -> dict[str, str]:
    return {k: v for rdn in rdns or () for (k, v) in rdn}


def inspect_tls(host: str, port: int, ip: str, timeout: float) -> TLSInfo:
    info = TLSInfo()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                info.verified = True
                info.protocol, info.cipher = s.version() or "", (s.cipher() or ("",))[0]
                cert = s.getpeercert() or {}
        info.subject_cn = _name(cert.get("subject")).get("commonName", "")
        issuer = _name(cert.get("issuer"))
        info.issuer = issuer.get("organizationName") or issuer.get("commonName", "")
        info.san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:20]
        if cert.get("notAfter"):
            info.not_after = cert["notAfter"]
            info.days_left = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
    except ssl.SSLCertVerificationError as e:
        info.verify_error = e.verify_message or str(e)
        try:  # secondo handshake senza verifica, solo per registrare protocollo e cifrario
            ctx = ssl._create_unverified_context()
            with socket.create_connection((ip, port), timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    info.protocol, info.cipher = s.version() or "", (s.cipher() or ("",))[0]
        except (OSError, ssl.SSLError):
            pass
    except (OSError, ssl.SSLError) as e:
        info.error = f"{e.__class__.__name__}: {e}"
    return info


def certificate_outcome(info: TLSInfo) -> CheckOutcome:
    det = {"subject_cn": info.subject_cn, "issuer": info.issuer, "not_after": info.not_after,
           "days_left": info.days_left, "san": info.san}
    if info.error:
        return CheckOutcome(FindingStatus.ERROR, Confidence.LOW,
                            f"Handshake TLS non riuscito: {info.error}", details=det)
    if not info.verified:
        return CheckOutcome(FindingStatus.CANDIDATE, Confidence.HIGH,
                            f"Certificato non valido per i browser: {info.verify_error}",
                            excerpt=info.verify_error, details={**det, "problem": "invalid"})
    if info.days_left is not None and info.days_left < EXPIRY_WARNING_DAYS:
        return CheckOutcome(FindingStatus.CANDIDATE, Confidence.HIGH,
                            f"Certificato valido ma in scadenza tra {info.days_left} giorni ({info.not_after})",
                            details={**det, "problem": "expiring"})
    return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.HIGH,
                        f"Certificato valido ({info.issuer}, scade il {info.not_after}, "
                        f"{info.days_left} giorni)", details=det)


def protocol_outcome(info: TLSInfo) -> CheckOutcome:
    if not info.protocol:
        return CheckOutcome(FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Versione TLS non determinata", details={"error": info.error})
    if info.protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        return CheckOutcome(FindingStatus.CANDIDATE, Confidence.HIGH,
                            f"Il server negozia {info.protocol}, protocollo obsoleto",
                            details={"protocol": info.protocol, "cipher": info.cipher})
    return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.MEDIUM,
                        f"Protocollo negoziato {info.protocol} ({info.cipher}). Il supporto a "
                        "versioni obsolete non è stato provato (limite dichiarato).",
                        details={"protocol": info.protocol, "cipher": info.cipher})
