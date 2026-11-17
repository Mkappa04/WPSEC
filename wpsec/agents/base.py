"""Classe base degli agenti.

Un agente dichiara: nome, dipendenze (ordine) e requisiti (agenti che devono essere
COMPLETATI perché abbia senso eseguirlo), se usa l'IA, e implementa run(ctx).
Gli agenti comunicano solo attraverso lo ScanContext.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from wpsec.core.context import ScanContext


class BaseAgent(ABC):
    name: str = ""
    display_name: str = ""
    description: str = ""
    depends_on: tuple[str, ...] = ()   # eseguito dopo questi agenti
    requires: tuple[str, ...] = ()     # saltato se uno di questi non è COMPLETATO
    uses_ai: bool = False
    phase: str = "check"               # "recon" | "check" | "analysis": solo i "check" sono pianificabili

    def should_run(self, ctx: ScanContext) -> tuple[bool, str]:
        return True, ""

    @abstractmethod
    def run(self, ctx: ScanContext) -> str:
        """Esegue il lavoro e ritorna un breve messaggio di esito."""


def error_outcome(resp):
    """Esito ERROR uniforme per una risposta con errore di rete o di perimetro."""
    from wpsec.core.models import Confidence, FindingStatus
    from wpsec.scanner.wordpress_checks import CheckOutcome
    return CheckOutcome(FindingStatus.ERROR, Confidence.LOW, resp.error or "errore sconosciuto",
                        details={"scope_blocked": resp.scope_blocked})


def annotate_block(ctx: ScanContext, outcome, resp) -> None:
    """Segna nei dettagli se la risposta sembra un blocco del WAF o un errore temporaneo.
    Non cambia lo stato: la decisione spetta all'Evidence Validation Agent."""
    from wpsec.scanner.fingerprint import looks_like_waf_block
    if resp.error:
        return
    if looks_like_waf_block(resp.status, resp.headers, resp.body, ctx.shared.get("waf", [])):
        outcome.details["waf_block"] = True
        outcome.details.setdefault("http_status", resp.status)
    elif resp.status >= 500:
        outcome.details["transient"] = True
        outcome.details.setdefault("http_status", resp.status)


def single_probe_check(ctx: ScanContext, agent: str, check_id: str, probe_id: str,
                       analyze: Callable, path: str) -> None:
    """Controllo basato su una sola sonda, con funzione di ricontrollo (richiesta fresca)."""

    def execute(fresh: bool = False):
        r = ctx.client.probe(probe_id, fresh=fresh)
        o = error_outcome(r) if not r.ok else analyze(r)
        annotate_block(ctx, o, r)
        return o, [r.evidence.id]

    outcome, ids = execute()
    ctx.add_finding(check_id, outcome, agent, ids, path=path, recheck=lambda: execute(True))
