"""Classe base degli agenti.

Un agente dichiara: nome, dipendenze (ordine) e requisiti (agenti che devono essere
COMPLETATI perché abbia senso eseguirlo), se usa l'IA, e implementa run(ctx).
Gli agenti comunicano solo attraverso lo ScanContext.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from wpsec.core.context import ScanContext


class BaseAgent(ABC):
    name: str = ""
    display_name: str = ""
    description: str = ""
    depends_on: tuple[str, ...] = ()   # eseguito dopo questi agenti
    requires: tuple[str, ...] = ()     # saltato se uno di questi non è COMPLETATO
    uses_ai: bool = False

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
