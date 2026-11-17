"""Evidence Validation Agent: decide lo stato finale di ogni risultato (solo codice, niente IA).

Regole (documentate anche in docs/METHODOLOGY.md):
  CANDIDATE
    - risposta che sembra un blocco del WAF            -> INCONCLUSIVE
    - controprova registrata (es. soft-404 di WordPress) -> FALSE_POSITIVE
    - confidenza bassa senza controprova               -> INCONCLUSIVE
    - altrimenti, con evidenze valide                  -> CONFIRMED
  NOT_DETECTED
    - blocco del WAF (sulla sonda o sulla home)        -> INCONCLUSIVE (non "protetto"!)
    - errore temporaneo / errori parziali / conf. bassa -> INCONCLUSIVE, poi ricontrollo
    - altrimenti                                       -> NOT_PRESENT
  ERROR
    - bloccato dal perimetro                           -> resta ERROR (non si riprova)
    - altrimenti                                       -> INCONCLUSIVE, poi ricontrollo
  INCONCLUSIVE (con funzione di ricontrollo e senza blocco WAF)
    - UN ricontrollo con richiesta fresca: esce da INCONCLUSIVE solo se il nuovo esito è netto.

Corregge i tre errori noti della v3 su wp-tricky: il 403 del WAF non è "protetto", la
parola "Index of" in una pagina del tema non è un directory listing.
"""

from __future__ import annotations

from wpsec.agents.base import BaseAgent
from wpsec.core.context import ScanContext, TransitionError
from wpsec.core.models import Confidence, Finding, FindingStatus

S = FindingStatus
WP_CATEGORIES = {"wordpress"}


class EvidenceValidationAgent(BaseAgent):
    name = "evidence"
    display_name = "Evidence Validation Agent"
    description = "Conferma o smentisce i risultati sulla base delle evidenze, con ricontrolli"
    depends_on = ("recon", "wordpress", "http")
    phase = "analysis"

    def run(self, ctx: ScanContext) -> str:
        stats = {"rechecks": 0, "recheck_resolved": 0}
        touched: list[Finding] = []
        for f in ctx.findings:
            before = len(f.history)
            ctx.client.check_cancelled()
            try:
                self._validate(ctx, f, stats)
            except TransitionError as e:
                ctx.log(self.name, "validation_error", str(e))
                if f.status in (S.CANDIDATE, S.NOT_DETECTED):
                    ctx.transition(f, S.INCONCLUSIVE, self.name, f"validazione impossibile: {e}")
            if len(f.history) > before:
                touched.append(f)
        for st in (S.CONFIRMED, S.FALSE_POSITIVE, S.NOT_PRESENT, S.INCONCLUSIVE):
            stats[st.value] = sum(1 for f in touched if f.status == st)
        with ctx.lock:
            ctx.result.stats["validation"] = stats
        return (f"{stats['confirmed']} confermati, {stats['false_positive']} falsi positivi, "
                f"{stats['not_present']} assenti, {stats['inconclusive']} inconcludenti "
                f"({stats['rechecks']} ricontrolli)")

    # ------------------------------------------------------------------
    def _validate(self, ctx: ScanContext, f: Finding, stats: dict):
        d = f.details
        waf = bool(d.get("waf_block")) or (
            f.category in WP_CATEGORIES and bool(ctx.shared.get("home_blocked")))

        if f.status == S.CANDIDATE:
            if waf:
                self._to(ctx, f, S.INCONCLUSIVE, "la risposta sembra un blocco del WAF: "
                         "l'esito non descrive il sito", stats, summary=self._waf_summary(f))
            elif d.get("counter_evidence"):
                self._to(ctx, f, S.FALSE_POSITIVE, f"smentito: {d['counter_evidence']}", stats)
            elif f.confidence == Confidence.LOW:
                self._to(ctx, f, S.INCONCLUSIVE, "indicazione debole senza conferma strutturale",
                         stats)
            else:
                self._to(ctx, f, S.CONFIRMED, "evidenza diretta registrata "
                         f"(confidenza {f.confidence.value})", stats)
            return

        if f.status == S.NOT_DETECTED:
            if waf:
                self._to(ctx, f, S.INCONCLUSIVE, "possibile blocco del WAF: non si può dire se "
                         "il problema sia assente o solo nascosto allo scanner", stats,
                         summary=self._waf_summary(f))
                return
            if d.get("transient") or d.get("partial_errors") or f.confidence == Confidence.LOW:
                self._to(ctx, f, S.INCONCLUSIVE, "esito non netto (errore temporaneo, risposta "
                         "parziale o confidenza bassa): serve un ricontrollo", stats)
                self._recheck(ctx, f, stats)
                return
            self._to(ctx, f, S.NOT_PRESENT, "assenza verificata dalla risposta del server", stats)
            return

        if f.status == S.ERROR:
            if d.get("scope_blocked") or f.check_id not in ctx.rechecks:
                return
            self._to(ctx, f, S.INCONCLUSIVE, "il controllo era fallito: ricontrollo", stats)
            self._recheck(ctx, f, stats)
            return

        if f.status == S.INCONCLUSIVE and not waf:
            self._recheck(ctx, f, stats)

    @staticmethod
    def _waf_summary(f: Finding) -> str:
        code = f.details.get("http_status")
        return (f"Non verificabile: la risposta{f' HTTP {code}' if code else ''} sembra un blocco "
                f"del WAF/CDN, non lo stato reale del sito. Esito grezzo: {f.summary}")[:500]

    def _to(self, ctx, f, status, reason, stats, **kw):
        ctx.transition(f, status, self.name, reason, **kw)

    def _recheck(self, ctx: ScanContext, f: Finding, stats: dict):
        fn = ctx.rechecks.get(f.check_id)
        if fn is None:
            return
        stats["rechecks"] += 1
        outcome, ids = fn()
        if outcome.excerpt and ids:
            ctx.set_excerpt(ids[-1], outcome.excerpt)
        od = outcome.details
        unclear = od.get("waf_block") or od.get("transient") or od.get("partial_errors")
        ctx.log(self.name, "recheck", f"{f.check_id}: {outcome.status.value}",
                confidence=outcome.confidence.value)
        if unclear or outcome.confidence == Confidence.LOW:
            return  # resta INCONCLUSIVE
        upd = dict(evidence_ids=ids, confidence=outcome.confidence, summary=outcome.summary,
                   details={**od, "rechecked": True})
        if outcome.status == S.CANDIDATE and not od.get("counter_evidence"):
            self._to(ctx, f, S.CONFIRMED, "confermato dal ricontrollo", stats, **upd)
            stats["recheck_resolved"] += 1
        elif outcome.status == S.NOT_DETECTED:
            self._to(ctx, f, S.NOT_PRESENT, "assenza verificata dal ricontrollo", stats, **upd)
            stats["recheck_resolved"] += 1
