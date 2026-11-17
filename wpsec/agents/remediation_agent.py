"""Remediation Agent: associa a ogni risultato CONFERMATO la correzione del catalogo.

Le correzioni sono scritte e verificate a mano (knowledge/remediation.py): l'IA non
genera codice né configurazioni. Può solo aggiungere un contesto ("perché serve, a cosa
fare attenzione"), marcato come contributo dell'IA. La piattaforma non applica mai
correzioni al sito.
"""

from __future__ import annotations

from wpsec.agents.base import BaseAgent
from wpsec.core.context import ScanContext
from wpsec.core.models import FindingStatus, RemediationAdvice
from wpsec.knowledge.catalog import get_definition
from wpsec.knowledge.remediation import TEMPLATES


class RemediationAgent(BaseAgent):
    name = "remediation"
    display_name = "Remediation Agent"
    description = "Correzioni verificate dal catalogo; contesto facoltativo dell'IA"
    depends_on = ("risk",)
    requires = ("evidence",)
    uses_ai = True
    phase = "analysis"

    def run(self, ctx: ScanContext) -> str:
        confirmed = sorted((f for f in ctx.findings if f.status == FindingStatus.CONFIRMED),
                           key=lambda f: (f.severity.rank if f.severity else 9, f.check_id))
        ai_context: dict[str, str] = {}   # una sola richiesta all'IA per correzione
        ai_budget = ctx.settings.ai_max_explanations
        done, missing = 0, []
        for f in confirmed:
            d = get_definition(f.check_id)
            t = TEMPLATES.get(d.remediation_id)
            if t is None:
                missing.append(f.check_id)
                continue
            if ctx.ai is not None and t.id not in ai_context and ai_budget > 0:
                ctx.client.check_cancelled()
                ai_budget -= 1
                note = ctx.ai.remediation_context(f, t)
                ai_context[t.id] = note.text if note else ""
                if note is not None:
                    ctx.add_ai_note(f, note, self.name)
            advice = RemediationAdvice(
                template_id=t.id, title=t.title, summary=t.summary, wordpress=t.wordpress,
                apache=t.apache, nginx=t.nginx, risks=t.risks, verification=t.verification,
                references=list(t.references or d.references), ai_context=ai_context.get(t.id, ""))
            ctx.set_assessment(f, self.name, remediation=advice)
            done += 1
        msg = f"{done} correzioni associate"
        if missing:
            msg += f"; senza correzione a catalogo: {', '.join(missing)}"
        return msg
