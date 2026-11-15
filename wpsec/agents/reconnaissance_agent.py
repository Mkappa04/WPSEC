"""Reconnaissance Agent: informazioni preliminari, solo GET in sola lettura.

Raccoglie: header della home, tecnologie, presenza di WordPress, WAF/CDN, percorsi
pubblici dichiarati in robots.txt, configurazione TLS (handshake diretto).
Se la home non è raggiungibile l'agente fallisce e gli agenti che lo richiedono
vengono saltati (il report lo dichiara).
"""

from __future__ import annotations

from wpsec.agents.base import BaseAgent, error_outcome
from wpsec.core.context import ScanContext
from wpsec.core.models import Confidence, FindingStatus
from wpsec.scanner import fingerprint as fp
from wpsec.scanner.wordpress_checks import CheckOutcome


class ReconnaissanceAgent(BaseAgent):
    name = "recon"
    display_name = "Reconnaissance Agent"
    description = "Tecnologie, WordPress, WAF/CDN, TLS e percorsi pubblici (non invasivo)"

    def run(self, ctx: ScanContext) -> str:
        c = ctx.client
        home = c.probe("home")
        if not home.ok:
            ctx.add_finding("recon.waf", error_outcome(home), self.name, [home.evidence.id])
            raise RuntimeError(f"target non raggiungibile: {home.error}")
        ctx.shared["home"] = home

        # --- WAF/CDN (informativo, come nella v3)
        waf = fp.detect_waf(home.headers)
        ctx.shared["waf"] = waf
        warning = ""
        if home.status in fp.BLOCKING_STATUSES:
            warning = (f" | ATTENZIONE: la home ha risposto HTTP {home.status}, il sito potrebbe "
                       "aver bloccato o limitato la scansione")
            ctx.shared["home_blocked"] = True
        summary = ("WAF/CDN rilevato: " + ", ".join(waf) if waf else
                   "Nessun WAF/CDN riconosciuto dagli header (non esclude che ci sia)") + warning
        ctx.add_finding("recon.waf", CheckOutcome(FindingStatus.INFO, Confidence.MEDIUM, summary,
                                                  details={"waf": waf}),
                        self.name, [home.evidence.id])

        # --- WordPress
        wpj = c.probe("wp_json_root")
        detected, conf, indicators = fp.detect_wordpress(home.status, home.headers, home.body,
                                                         wpj.status, wpj.body)
        ctx.shared["wordpress"] = {"detected": detected, "confidence": conf,
                                   "indicators": indicators}
        ctx.add_finding("recon.wordpress", CheckOutcome(
            FindingStatus.INFO, Confidence(conf),
            ("WordPress rilevato: " if detected else "WordPress non rilevato. Indicatori: ")
            + ("; ".join(indicators) or "nessuno"),
            details=ctx.shared["wordpress"]), self.name, [home.evidence.id, wpj.evidence.id])

        # --- tecnologie e percorsi pubblici
        tech = fp.detect_technologies(home.headers, home.body)
        robots = c.probe("robots")
        paths = fp.robots_paths(robots.status, robots.body)
        with ctx.lock:
            ctx.result.technologies.update(tech)
            ctx.result.technologies["wordpress"] = "sì" if detected else "no"
            if waf:
                ctx.result.technologies["waf_cdn"] = ", ".join(waf)
            if paths:
                ctx.result.technologies["robots_txt"] = ", ".join(paths)
        ctx.add_finding("recon.technologies", CheckOutcome(
            FindingStatus.INFO, Confidence.MEDIUM,
            "; ".join(f"{k}: {v}" for k, v in tech.items()) or "Nessuna tecnologia dichiarata negli header",
            details={"technologies": tech, "robots_paths": paths}),
            self.name, [home.evidence.id, robots.evidence.id])

        # --- TLS (valutato dall'HTTP Security Agent)
        if ctx.result.authorization and c.target.scheme == "https":
            try:
                ctx.shared["tls"] = c.tls_inspect()
            except Exception as e:  # handshake fallito: lo valuta l'HTTP agent
                ctx.shared["tls_error"] = str(e)
        return (f"WordPress {'rilevato' if detected else 'non rilevato'} ({conf}); "
                f"WAF: {', '.join(waf) or 'nessuno'}")
