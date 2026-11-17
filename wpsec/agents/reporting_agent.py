"""Reporting Agent: limiti dell'analisi e sintesi per la direzione.

La sintesi deterministica è sempre calcolata; se l'IA è disponibile ne scrive una
versione più leggibile, usando SOLO conteggi e titoli forniti dal codice. Se l'IA
fallisce resta quella deterministica. I file del report (HTML/PDF/JSON) sono prodotti
dal modulo reports, a scansione conclusa.
"""

from __future__ import annotations

from wpsec.agents.base import BaseAgent
from wpsec.core.context import ScanContext
from wpsec.core.models import AgentState, FindingStatus, Severity

S = FindingStatus


def limitations(ctx: ScanContext) -> list[str]:
    r = ctx.result
    out = ["Analisi non invasiva: nessun tentativo di login, exploit, brute force o test di "
           "iniezione; solo pagine pubbliche senza autenticazione.",
           "L'assenza di un problema indica che non è stato rilevato con i controlli eseguiti, "
           "non che il sito ne sia privo."]
    if ctx.client is not None and ctx.client.target.scheme == "https":
        out.append("TLS: registrata la versione negoziata; il supporto a versioni obsolete "
                   "non è stato provato.")
    waf = ctx.shared.get("waf") or []
    if waf:
        out.append(f"WAF/CDN rilevato ({', '.join(waf)}): alcune risposte possono provenire "
                   "dal WAF e non dal sito.")
    inc = [f.title for f in r.findings if f.status == S.INCONCLUSIVE]
    if inc:
        out.append(f"{len(inc)} controlli inconcludenti: {', '.join(inc[:6])}.")
    err = [f.title for f in r.findings if f.status == S.ERROR]
    if err:
        out.append(f"{len(err)} controlli non eseguiti per errore: {', '.join(err[:6])}.")
    for a in r.agents:
        if a.state in (AgentState.SKIPPED, AgentState.FAILED):
            what = "saltato" if a.state == AgentState.SKIPPED else "fallito"
            out.append(f"{a.display_name} {what}: {a.message or a.error or ''}".rstrip(": ") + ".")
    if ctx.client is not None and ctx.client.stats.get("requests", 0) >= ctx.settings.max_requests:
        out.append(f"Raggiunto il budget di {ctx.settings.max_requests} richieste.")
    if r.authorization and not r.options.use_ai:
        out.append("IA disattivata dall'operatore: spiegazioni e sintesi sono solo deterministiche.")
    elif ctx.ai is None and r.options.use_ai:
        out.append("IA locale non disponibile: spiegazioni e sintesi sono solo deterministiche.")
    return out


def deterministic_summary(ctx: ScanContext) -> str:
    r = ctx.result
    confirmed = sorted((f for f in r.findings if f.status == S.CONFIRMED),
                       key=lambda f: (f.severity.rank if f.severity else 9, f.check_id))
    sev = r.severity_counts()
    parts = [f"Analisi non invasiva di {r.host}: {len(confirmed)} problemi confermati"]
    detail = ", ".join(f"{v} {Severity(k).label_it.lower()}" for k, v in sev.items() if v)
    if detail:
        parts[0] += f" ({detail})"
    parts[0] += "."
    if confirmed:
        parts.append("Principali: " + "; ".join(
            f"{f.title} [{f.severity.label_it if f.severity else '?'}]" for f in confirmed[:5]) + ".")
    c = r.counts()
    if c.get("inconclusive"):
        parts.append(f"{c['inconclusive']} controlli inconcludenti da verificare manualmente.")
    if c.get("false_positive"):
        parts.append(f"{c['false_positive']} indicazioni scartate come falsi positivi.")
    return " ".join(parts)


class ReportingAgent(BaseAgent):
    name = "reporting"
    display_name = "Reporting Agent"
    description = "Limiti dell'analisi e sintesi per la direzione (IA facoltativa)"
    depends_on = ("remediation",)
    uses_ai = True
    phase = "analysis"

    def run(self, ctx: ScanContext) -> str:
        lims = limitations(ctx)
        text, ai = deterministic_summary(ctx), False
        if ctx.ai is not None:
            ai_text = ctx.ai.summarize(ctx.snapshot(), lims)
            if ai_text:
                text, ai = ai_text, True
        ctx.set_summary(self.name, text, ai, lims)
        return f"sintesi {'IA' if ai else 'deterministica'}, {len(lims)} limiti dichiarati"
