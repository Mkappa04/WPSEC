"""Implementazione di AIProvider basata su Ollama locale (OllamaClient + prompts + validator).

Regole:
  - ogni risposta è validata con uno schema Pydantic; se non è valida si riprova fino a
    settings.ai_retries volte, poi si rinuncia (None): l'agente prosegue senza IA;
  - se Ollama non è raggiungibile, l'assistente si disattiva per il resto della scansione
    (nessun tentativo ripetuto a vuoto);
  - l'IA non vede mai URL da contattare né può cambiare stati, gravità o correzioni.
"""

from __future__ import annotations

import threading

from wpsec.ai import prompts
from wpsec.ai.ollama_client import OllamaClient, OllamaError, OllamaUnavailable
from wpsec.ai.validator import (AIValidationError, ExplanationOut, PlannerOut,
                                RemediationContextOut, SummaryOut, validate_response)
from wpsec.config.settings import Settings
from wpsec.core.models import AINote, Finding, FindingStatus, ScanResult
from wpsec.knowledge.remediation import RemediationTemplate


class OllamaAssistant:
    def __init__(self, client: OllamaClient, model: str, settings: Settings):
        self.client = client
        self.model = model
        self.settings = settings
        self.disabled_reason = ""
        self._lock = threading.Lock()
        self.stats = {"calls": 0, "valid": 0, "invalid": 0, "errors": 0, "gave_up": 0}

    # ------------------------------------------------------------ interno
    def _ask(self, prompt: str, schema):
        """Ritorna (oggetto validato, tentativi) oppure (None, tentativi)."""
        if self.disabled_reason:
            return None, 0
        attempts = 0
        for _ in range(1 + max(0, self.settings.ai_retries)):
            attempts += 1
            with self._lock:
                self.stats["calls"] += 1
            try:
                text = self.client.generate(prompt, self.model, self.settings.ai_seed,
                                            self.settings.ai_max_tokens)
                out = validate_response(text, schema)
                with self._lock:
                    self.stats["valid"] += 1
                return out, attempts
            except OllamaUnavailable as e:
                self.disabled_reason = f"Ollama non raggiungibile: {e}"
                with self._lock:
                    self.stats["errors"] += 1
                return None, attempts
            except AIValidationError:
                with self._lock:
                    self.stats["invalid"] += 1
            except OllamaError:
                with self._lock:
                    self.stats["errors"] += 1
        with self._lock:
            self.stats["gave_up"] += 1
        return None, attempts

    def _note(self, agent: str, purpose: str, text: str, attempts: int, priority=None) -> AINote:
        return AINote(agent=agent, model=self.model, purpose=purpose, text=text[:1200],
                      suggested_priority=priority, prompt_version=prompts.PROMPT_VERSION,
                      attempts=attempts)

    # ------------------------------------------------------------ AIProvider
    def explain(self, finding: Finding) -> AINote | None:
        if finding.status != FindingStatus.CONFIRMED:
            return None
        sev = finding.severity.value if finding.severity else "non assegnata"
        p = prompts.explain_prompt(finding.title, finding.kind.value, sev, finding.path,
                                   finding.summary)
        out, n = self._ask(p, ExplanationOut)
        if out is None:
            return None
        return self._note("risk", "explanation", out.spiegazione, n, out.priorita)

    def remediation_context(self, finding: Finding, template: RemediationTemplate) -> AINote | None:
        p = prompts.remediation_prompt(finding.title, finding.summary, template.summary,
                                       template.risks)
        out, n = self._ask(p, RemediationContextOut)
        if out is None:
            return None
        return self._note("remediation", "remediation_context", out.contesto, n)

    def summarize(self, result: ScanResult, limitations: list[str]) -> str | None:
        counts = ", ".join(f"{k}={v}" for k, v in sorted(result.counts().items()))
        sev = ", ".join(f"{k}={v}" for k, v in result.severity_counts().items() if v)
        top = sorted((f for f in result.findings if f.status == FindingStatus.CONFIRMED),
                     key=lambda f: f.severity.rank if f.severity else 9)[:6]
        top_text = "; ".join(f"{f.title} ({f.severity.label_it if f.severity else '?'})"
                             for f in top) or "nessuno"
        p = prompts.summary_prompt(result.host, f"{counts}; gravità: {sev or 'nessuna'}",
                                   top_text, "; ".join(limitations))
        out, _ = self._ask(p, SummaryOut)
        return out.sintesi if out else None

    def plan(self, menu: list[tuple[str, str]], summaries: dict[str, str],
             steps_left: int, seed: int) -> tuple[str | None, str, str | None]:
        allowed = {name for name, _ in menu} | {"fine"}
        out, _ = self._ask(prompts.planner_prompt(menu, summaries, steps_left), PlannerOut)
        if out is None:
            return None, "", self.disabled_reason or "risposta non valida"
        if out.azione not in allowed:
            return None, out.motivo, f"azione non ammessa: {out.azione[:40]}"
        return out.azione, out.motivo, None


def build_assistant(settings: Settings, model: str = "",
                    cancel_event: threading.Event | None = None) -> tuple[OllamaAssistant | None, str]:
    """Crea l'assistente se Ollama e il modello sono disponibili. Ritorna (assistente, nota)."""
    from wpsec.ai.ollama_client import discover_ollama
    url, models = discover_ollama(settings.ollama_url)
    if not url:
        return None, "Ollama non raggiungibile: analisi senza IA"
    wanted = model or settings.default_model
    if wanted not in models:
        return None, f"modello {wanted} non presente in Ollama ({', '.join(models[:5]) or 'nessuno'})"
    client = OllamaClient(url, settings.ai_timeout, settings.ai_num_gpu, cancel_event)
    return OllamaAssistant(client, wanted, settings), f"IA locale: {wanted} su {url}"
