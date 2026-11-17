"""HTTP Security Agent: header di sicurezza, informazioni negli header, cookie,
redirect HTTP -> HTTPS e TLS.

Lavora quasi interamente sulla risposta della home già scaricata dalla Reconnaissance
(cache: nessuna richiesta ripetuta) e sull'handshake TLS già eseguito. L'unica richiesta
nuova è la versione HTTP del sito, e solo se l'origine http:// è nel perimetro.
"""

from __future__ import annotations

from wpsec.agents.base import BaseAgent, annotate_block, error_outcome
from wpsec.core.context import ScanContext
from wpsec.core.models import Confidence, Evidence, FindingStatus, Origin
from wpsec.scanner import security_headers as sh
from wpsec.scanner import tls_checks
from wpsec.scanner.wordpress_checks import CheckOutcome

S, C = FindingStatus, Confidence


class HttpSecurityAgent(BaseAgent):
    name = "http"
    display_name = "HTTP Security Agent"
    description = "Header di sicurezza, header informativi, cookie, redirect a HTTPS, TLS"
    depends_on = ("recon",)
    requires = ("recon",)

    def run(self, ctx: ScanContext) -> str:
        home = ctx.shared.get("home") or ctx.client.probe("home")
        if not home.ok:
            raise RuntimeError(f"home non disponibile: {home.error}")
        scheme = ctx.client.target.scheme
        ev = [home.evidence.id]
        blocked = bool(ctx.shared.get("home_blocked"))

        # --- header di sicurezza: un risultato per header
        for a in sh.analyze_security_headers(home.headers, scheme):
            o = self._header_outcome(a)
            if blocked:
                o.details["waf_block"] = True
            ctx.add_finding(a.check_id, o, self.name, ev, path="/")

        # --- header che rivelano software e versioni
        disc = sh.disclosure_headers(home.headers)
        if disc:
            shown = "; ".join(f"{k}: {v}" for k, v in disc.items())
            o = CheckOutcome(S.CANDIDATE, C.HIGH, f"Header con software/versioni: {shown}",
                             excerpt=shown, details={"headers": disc})
        else:
            o = CheckOutcome(S.NOT_DETECTED, C.HIGH, "Nessun header rivela versioni del software")
        ctx.add_finding("http.info_disclosure", o, self.name, ev)

        # --- cookie
        ctx.add_finding("http.cookies", self._cookies_outcome(home.set_cookies, scheme),
                        self.name, ev)

        # --- redirect HTTP -> HTTPS
        self._https_redirect(ctx)

        # --- TLS
        self._tls(ctx)
        n = sum(1 for f in ctx.findings if f.agent == self.name and f.status == S.CANDIDATE)
        return f"{n} candidati su header, cookie, redirect e TLS"

    # ------------------------------------------------------------ header
    @staticmethod
    def _header_outcome(a: sh.HeaderAssessment) -> CheckOutcome:
        det = {"header": a.header, "value": a.value[:200], "issues": a.issues,
               "assessment": a.status, "explanation": a.explanation}
        if a.status == "not_applicable":
            return CheckOutcome(S.NOT_APPLICABLE, C.HIGH, f"{a.header}: " + "; ".join(a.issues),
                                details=det)
        if a.status == "missing":
            extra = (" (" + "; ".join(a.issues) + ")") if a.issues else ""
            return CheckOutcome(S.CANDIDATE, C.HIGH, f"{a.header} assente{extra}", details=det)
        if a.status == "weak":
            return CheckOutcome(S.CANDIDATE, C.HIGH,
                                f"{a.header} presente ma debole: " + "; ".join(a.issues),
                                excerpt=f"{a.header}: {a.value}", details=det)
        note = (" (" + "; ".join(a.issues) + ")") if a.issues else ""
        return CheckOutcome(S.NOT_DETECTED, C.HIGH, f"{a.header} presente e adeguato{note}",
                            excerpt=f"{a.header}: {a.value}" if a.value else "", details=det)

    @staticmethod
    def _cookies_outcome(set_cookies: list[str], scheme: str) -> CheckOutcome:
        if not set_cookies:
            return CheckOutcome(S.NOT_APPLICABLE, C.HIGH,
                                "La home non imposta cookie per i visitatori non autenticati")
        problems = {}
        for c in sh.analyze_cookies(set_cookies):
            missing = []
            if scheme == "https" and not c.secure:
                missing.append("secure")
            if not c.httponly:
                missing.append("httponly")
            if not c.samesite:
                missing.append("samesite")
            if missing:
                problems[c.name[:60]] = missing
        if not problems:
            return CheckOutcome(S.NOT_DETECTED, C.HIGH,
                                f"{len(set_cookies)} cookie con Secure/HttpOnly/SameSite")
        shown = "; ".join(f"{n}: manca {', '.join(m)}" for n, m in problems.items())
        return CheckOutcome(S.CANDIDATE, C.HIGH, f"Cookie senza attributi di sicurezza: {shown}",
                            excerpt=shown, details={"cookies": problems})

    # ------------------------------------------------------------ redirect
    def _https_redirect(self, ctx: ScanContext):
        target = ctx.client.target
        if target.scheme != "https":
            ctx.add_finding("http.https_redirect", CheckOutcome(
                S.NOT_APPLICABLE, C.HIGH,
                "Il target è analizzato in HTTP: la verifica del redirect a HTTPS non si applica "
                "(vedi il risultato sulla disponibilità di HTTPS)"), self.name)
            return
        http_origin = Origin(scheme="http", host=target.host, port=80)
        if not ctx.result.authorization.covers(http_origin):
            ctx.add_finding("http.https_redirect", CheckOutcome(
                S.NOT_APPLICABLE, C.HIGH,
                f"{http_origin.url} non è nel perimetro autorizzato: redirect non verificato",
                details={"out_of_scope": True}), self.name)
            return

        def execute(fresh: bool = False):
            r = ctx.client.probe("http_redirect", fresh=fresh)
            if not r.ok:
                if "refused" in (r.error or "").lower():
                    o = CheckOutcome(S.NOT_DETECTED, C.MEDIUM,
                                     "La porta 80 non accetta connessioni: il sito non risponde in chiaro",
                                     details={"error": r.error})
                else:
                    o = error_outcome(r)
                return o, [r.evidence.id]
            loc = r.headers.get("location", "")
            if r.status in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
                o = CheckOutcome(S.NOT_DETECTED, C.HIGH,
                                 f"HTTP {r.status} verso {loc[:120]}" +
                                 ("" if r.status in (301, 308) else " (redirect non permanente)"),
                                 details={"http_status": r.status, "permanent": r.status in (301, 308)})
            elif r.status in (301, 302, 303, 307, 308):
                o = CheckOutcome(S.CANDIDATE, C.HIGH,
                                 f"HTTP {r.status} ma verso un indirizzo non HTTPS: {loc[:120]}",
                                 excerpt=f"Location: {loc[:120]}", details={"http_status": r.status})
            elif r.status == 200:
                o = CheckOutcome(S.CANDIDATE, C.HIGH,
                                 "Il sito risponde in HTTP (200) senza reindirizzare a HTTPS",
                                 details={"http_status": 200})
            else:
                o = CheckOutcome(S.NOT_DETECTED, C.LOW,
                                 f"Versione HTTP: risposta HTTP {r.status} senza redirect",
                                 details={"http_status": r.status})
                annotate_block(ctx, o, r)
            return o, [r.evidence.id]

        o, ids = execute()
        ctx.add_finding("http.https_redirect", o, self.name, ids, recheck=lambda: execute(True))

    # ------------------------------------------------------------ TLS
    def _tls(self, ctx: ScanContext):
        target = ctx.client.target
        if target.scheme != "https":
            ctx.add_finding("tls.https", CheckOutcome(
                S.INFO, C.HIGH, "Il target è in HTTP: controlli TLS e HSTS non applicabili. "
                                "Se il sito ha anche una versione HTTPS va autorizzata e analizzata."),
                self.name)
            for cid in ("tls.certificate", "tls.protocol"):
                ctx.add_finding(cid, CheckOutcome(S.NOT_APPLICABLE, C.HIGH, "Target in HTTP"),
                                self.name)
            return
        info = ctx.shared.get("tls")
        if info is None:
            info = tls_checks.TLSInfo(error=ctx.shared.get("tls_error", "handshake non eseguito"))
        ev = Evidence(probe_id="tls_handshake", method="TLS", url=target.url,
                      error=info.error or None,
                      excerpt=(f"protocollo={info.protocol} cifrario={info.cipher} "
                               f"emittente={info.issuer} scadenza={info.not_after} "
                               f"verificato={'sì' if info.verified else 'no: ' + info.verify_error}")[:300])
        ctx.register_evidence(ev)
        ctx.add_finding("tls.https", CheckOutcome(S.INFO, C.HIGH, "Il sito è servito in HTTPS"),
                        self.name, [ev.id])
        ctx.add_finding("tls.certificate", tls_checks.certificate_outcome(info), self.name, [ev.id])
        ctx.add_finding("tls.protocol", tls_checks.protocol_outcome(info), self.name, [ev.id])
