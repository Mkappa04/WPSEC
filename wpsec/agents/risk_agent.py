"""Risk Assessment Agent: gravità, priorità, impatto e CWE dei risultati CONFERMATI.

La gravità viene SOLO dal catalogo, con poche regole esplicite basate sulle evidenze
(es. XML-RPC con system.multicall). La probabilità viene indicata solo quando una
correlazione fra risultati confermati la giustifica. Il CVSS resta vuoto se il catalogo
non ne fornisce uno giustificabile.

L'IA (facoltativa) aggiunge una spiegazione e una priorità SUGGERITA, salvate come nota
separata: non modificano gravità né priorità.
"""

from __future__ import annotations

from wpsec.agents.base import BaseAgent
from wpsec.core.context import ScanContext
from wpsec.core.models import Finding, FindingStatus, Severity
from wpsec.knowledge.catalog import COOKIE_CWE, get_definition

PRIORITY = {Severity.CRITICAL: "P1", Severity.HIGH: "P2", Severity.MEDIUM: "P3",
            Severity.LOW: "P4", Severity.INFO: "P4"}


def severity_for(f: Finding) -> tuple[Severity, str]:
    """Gravità del catalogo più le regole basate sulle evidenze. Ritorna (gravità, motivo)."""
    d = get_definition(f.check_id)
    if f.check_id == "wp.xmlrpc":
        if f.details.get("multicall"):
            return Severity.MEDIUM, "system.multicall presente: tentativi di password amplificati"
        return Severity.LOW, "system.multicall non presente: superficie d'attacco ridotta"
    if f.check_id == "tls.certificate" and f.details.get("problem") == "expiring":
        return Severity.LOW, "certificato ancora valido: il rischio è l'interruzione futura"
    if f.check_id.startswith("zap.") and f.details.get("zap_risk"):
        mapping = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
                   "informational": Severity.INFO}
        return mapping.get(str(f.details["zap_risk"]).lower(), d.severity), "gravità indicata da ZAP"
    return d.severity, ""


def cwe_for(f: Finding) -> str:
    if f.check_id == "http.cookies":
        missing = {a for attrs in f.details.get("cookies", {}).values() for a in attrs}
        return ", ".join(COOKIE_CWE[a] for a in ("secure", "httponly") if a in missing)
    if f.check_id.startswith("zap.") and f.details.get("cwe"):
        return f"CWE-{f.details['cwe']}"
    return get_definition(f.check_id).cwe


class RiskAssessmentAgent(BaseAgent):
    name = "risk"
    display_name = "Risk Assessment Agent"
    description = "Gravità e priorità dal catalogo; spiegazione facoltativa dell'IA"
    depends_on = ("evidence",)
    requires = ("evidence",)
    uses_ai = True
    phase = "analysis"

    def run(self, ctx: ScanContext) -> str:
        confirmed = [f for f in ctx.findings if f.status == FindingStatus.CONFIRMED]
        by_id = {f.check_id: f for f in confirmed}
        for f in confirmed:
            d = get_definition(f.check_id)
            sev, why = severity_for(f)
            ctx.set_assessment(
                f, self.name, severity=sev, priority=PRIORITY[sev], impact=d.impact,
                rationale=d.rationale + (f" Regola applicata: {why}." if why else ""),
                cwe=cwe_for(f), cvss_vector=d.cvss_vector,
                likelihood=self._likelihood(f, by_id))

        explained = 0
        if ctx.ai is not None:
            ranked = sorted(confirmed, key=lambda f: (f.severity.rank, f.check_id))
            for f in ranked[: ctx.settings.ai_max_explanations]:
                ctx.client.check_cancelled()
                note = ctx.ai.explain(f)
                if note is not None:
                    ctx.add_ai_note(f, note, self.name)
                    explained += 1
        counts = ctx.result.severity_counts()
        return (", ".join(f"{Severity(k).label_it}: {v}" for k, v in counts.items() if v)
                or "nessun risultato confermato") + (f"; {explained} spiegazioni IA" if ctx.ai else "")

    @staticmethod
    def _likelihood(f: Finding, confirmed: dict[str, Finding]) -> str:
        """Solo correlazioni dimostrate da altri risultati confermati."""
        user_leak = "wp.users_rest" in confirmed or "wp.author_enum" in confirmed
        if f.check_id in ("wp.users_rest", "wp.author_enum") and "wp.xmlrpc" in confirmed \
                and confirmed["wp.xmlrpc"].details.get("multicall"):
            return ("Più alta: gli username esposti possono essere usati subito in tentativi di "
                    "password amplificati tramite XML-RPC (system.multicall, confermato).")
        if f.check_id == "wp.xmlrpc" and f.details.get("multicall") and user_leak:
            return ("Più alta: gli username sono già esposti (risultato confermato), quindi un "
                    "attacco alle password tramite XML-RPC non richiede di indovinarli.")
        return ""
