"""Interfaccia che un fornitore di IA deve rispettare per essere usato dagli agenti.

Gli agenti NON dipendono da Ollama: ricevono (facoltativamente) un oggetto con questi
metodi. Se è assente, o se un metodo restituisce None, l'agente prosegue con i soli
dati deterministici. L'implementazione basata su OllamaClient + validator.py va
collocata in wpsec/ai/assistant.py (da completare: vedi docs/DEVELOPMENT_LOG.md).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from wpsec.core.models import AINote, Finding, ScanResult
from wpsec.knowledge.remediation import RemediationTemplate


@runtime_checkable
class AIProvider(Protocol):
    model: str
    stats: dict

    def explain(self, finding: Finding) -> AINote | None:
        """Spiegazione e priorità suggerita per un risultato CONFERMATO."""

    def remediation_context(self, finding: Finding, template: RemediationTemplate) -> AINote | None:
        """Contesto della correzione già scelta dal catalogo (nessun codice nuovo)."""

    def summarize(self, result: ScanResult, limitations: list[str]) -> str | None:
        """Sintesi per la direzione, basata solo sui dati forniti."""

    def plan(self, menu: list[tuple[str, str]], summaries: dict[str, str],
             steps_left: int, seed: int) -> tuple[str | None, str, str | None]:
        """Decisione del pianificatore: (azione, motivo, errore)."""
