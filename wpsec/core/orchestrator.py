"""Orchestratore: esegue gli agenti nell'ordine imposto dalle dipendenze.

Garanzie:
  - ordine topologico dalle dipendenze dichiarate (ciclo o dipendenza ignota = errore
    di configurazione, prima di qualunque richiesta);
  - un agente con un requisito non COMPLETATO viene SALTATO, con il motivo;
  - un'eccezione in un agente lo marca FAILED senza fermare gli altri (errori isolati);
  - timeout per agente: allo scadere l'agente è marcato FAILED e non può più scrivere
    nel contesto (ScanContext.close_writer);
  - l'annullamento della scansione ferma tutto alla prima occasione;
  - ogni decisione finisce nella traccia (ScanResult.trace).

Pianificazione: le fasi "recon" e "analysis" sono sempre in ordine fisso. Solo l'ordine
degli agenti di controllo ("check") può essere scelto da un pianificatore. Il pianificatore
LLM è sperimentale (per ripetere il confronto del benchmark): sceglie solo l'ORDINE, non
può saltare controlli, e dopo planner_max_invalid decisioni non valide si torna all'ordine fisso.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from wpsec.agents.base import BaseAgent
from wpsec.core.context import ScanContext
from wpsec.core.models import AgentRun, AgentState, now_utc
from wpsec.scanner.http_client import Cancelled

PHASES = ("recon", "check", "analysis")


class OrchestratorConfigError(Exception):
    """Grafo degli agenti non valido (ciclo, dipendenza o nome duplicato)."""


def topological_order(agents: list[BaseAgent]) -> list[BaseAgent]:
    by_name: dict[str, BaseAgent] = {}
    for a in agents:
        if not a.name or a.name in by_name:
            raise OrchestratorConfigError(f"nome di agente mancante o duplicato: {a.name!r}")
        if a.phase not in PHASES:
            raise OrchestratorConfigError(f"{a.name}: fase sconosciuta {a.phase!r}")
        by_name[a.name] = a
    for a in agents:
        for dep in (*a.depends_on, *a.requires):
            if dep not in by_name:
                raise OrchestratorConfigError(f"{a.name} dipende da un agente sconosciuto: {dep}")
    order: list[BaseAgent] = []
    state: dict[str, int] = {}  # 1 = in visita, 2 = fatto

    def visit(a: BaseAgent, path: tuple[str, ...]):
        if state.get(a.name) == 2:
            return
        if state.get(a.name) == 1:
            raise OrchestratorConfigError("dipendenze circolari: " + " -> ".join((*path, a.name)))
        state[a.name] = 1
        for dep in dict.fromkeys((*a.depends_on, *a.requires)):
            visit(by_name[dep], (*path, a.name))
        state[a.name] = 2
        order.append(a)

    for a in agents:
        visit(a, ())
    # le fasi devono rispettare l'ordine recon -> check -> analysis
    for a in order:
        for dep in a.depends_on:
            if PHASES.index(by_name[dep].phase) > PHASES.index(a.phase):
                raise OrchestratorConfigError(f"{a.name} ({a.phase}) dipende da {dep} di una fase successiva")
    return sorted(order, key=lambda a: PHASES.index(a.phase))  # sort stabile: topologico nella fase


class Orchestrator:
    def __init__(self, ctx: ScanContext, agents: list[BaseAgent],
                 on_update: Callable[[ScanContext], None] | None = None):
        self.ctx = ctx
        self.agents = topological_order(agents)
        self.on_update = on_update
        self.runs: dict[str, AgentRun] = {}
        for a in self.agents:
            run = AgentRun(name=a.name, display_name=a.display_name or a.name, uses_ai=a.uses_ai)
            self.runs[a.name] = run
        with ctx.lock:
            ctx.result.agents = list(self.runs.values())

    # ------------------------------------------------------------ esecuzione
    def run(self):
        ctx = self.ctx
        ctx.log("orchestrator", "plan", " -> ".join(a.name for a in self.agents),
                planner=ctx.result.options.planner)
        for phase in PHASES:
            group = [a for a in self.agents if a.phase == phase]
            if phase == "check" and ctx.result.options.planner == "llm" and ctx.ai is not None:
                group = self._llm_order(group)
            for agent in group:
                self._run_agent(agent)

    def _notify(self):
        if self.on_update:
            try:
                self.on_update(self.ctx)
            except Exception as e:  # l'interfaccia non deve mai fermare la scansione
                self.ctx.log("orchestrator", "update_error", str(e))

    def _finish(self, run: AgentRun, state: AgentState, message: str = "", error: str | None = None):
        with self.ctx.lock:
            run.state = state
            run.message = message[:300]
            run.error = error[:300] if error else None
            if run.started_at:
                run.finished_at = now_utc()
                run.duration_s = round((run.finished_at - run.started_at).total_seconds(), 3)

    def _run_agent(self, agent: BaseAgent):
        ctx, run = self.ctx, self.runs[agent.name]
        if ctx.client is not None:
            ctx.client.check_cancelled()
        missing = [r for r in agent.requires if self.runs[r].state != AgentState.COMPLETED]
        if missing:
            msg = f"requisito non soddisfatto: {', '.join(missing)} non completato"
            self._finish(run, AgentState.SKIPPED, msg)
            ctx.log("orchestrator", "agent_skipped", f"{agent.name}: {msg}")
            self._notify()
            return
        ok, reason = agent.should_run(ctx)
        if not ok:
            self._finish(run, AgentState.SKIPPED, reason)
            ctx.log("orchestrator", "agent_skipped", f"{agent.name}: {reason}")
            self._notify()
            return
        if reason:
            ctx.log("orchestrator", "agent_note", f"{agent.name}: {reason}")

        req0 = ctx.client.stats["requests"] if ctx.client is not None else 0
        with ctx.lock:
            run.state, run.started_at = AgentState.RUNNING, now_utc()
        ctx.log("orchestrator", "agent_start", agent.name)
        self._notify()

        box: dict = {}

        def target():
            try:
                box["message"] = agent.run(ctx) or ""
            except BaseException as e:  # noqa: BLE001 - riportata sotto
                box["exc"] = e

        t = threading.Thread(target=target, name=f"agent-{agent.name}", daemon=True)
        t.start()
        t.join(ctx.settings.agent_timeout)

        if t.is_alive():
            ctx.close_writer(agent.name)
            err = f"timeout dopo {ctx.settings.agent_timeout:.0f}s"
            self._finish(run, AgentState.FAILED, error=err)
            ctx.log("orchestrator", "agent_timeout", f"{agent.name}: {err}")
        elif isinstance(box.get("exc"), Cancelled):
            self._finish(run, AgentState.FAILED, error="scansione annullata")
            ctx.log("orchestrator", "cancelled", agent.name)
            self._notify()
            raise box["exc"]
        elif "exc" in box:
            e = box["exc"]
            err = f"{e.__class__.__name__}: {e}"
            self._finish(run, AgentState.FAILED, error=err)
            ctx.log("orchestrator", "agent_failed", f"{agent.name}: {err}")
        else:
            self._finish(run, AgentState.COMPLETED, box.get("message", ""))
            ctx.log("orchestrator", "agent_end", f"{agent.name}: {box.get('message', '')}")
        with ctx.lock:
            if ctx.client is not None:
                run.requests = ctx.client.stats["requests"] - req0
            run.findings = sum(1 for f in ctx.result.findings if f.agent == agent.name)
        self._notify()

    # ------------------------------------------------------------ pianificatore LLM
    def _llm_order(self, group: list[BaseAgent]) -> list[BaseAgent]:
        ctx = self.ctx
        pending = list(group)
        ordered: list[BaseAgent] = []
        invalid = 0
        summaries = {n: r.message for n, r in self.runs.items() if r.state == AgentState.COMPLETED}
        stats = {"decisions": 0, "invalid": 0, "fallback": False}
        while pending:
            if invalid >= ctx.settings.planner_max_invalid:
                stats["fallback"] = True
                ctx.log("planner", "fallback", f"{invalid} decisioni non valide: ordine fisso")
                break
            pending_names = {a.name for a in pending}
            ready = [a for a in pending if not pending_names & set(a.depends_on)]
            menu = [(a.name, a.description) for a in ready]
            steps_left = max(ctx.settings.planner_max_steps - stats["decisions"], 1)
            action, why, error = ctx.ai.plan(menu, summaries, steps_left, ctx.settings.ai_seed)
            stats["decisions"] += 1
            if error or action is None:
                invalid += 1
                stats["invalid"] += 1
                ctx.log("planner", "invalid_decision", error or "nessuna azione")
                continue
            if action == "fine":
                # il pianificatore non può saltare controlli: la richiesta viene registrata
                ctx.log("planner", "end_refused", "controlli ancora da eseguire: "
                        + ", ".join(a.name for a in pending), reason=why)
                break
            chosen = next(a for a in ready if a.name == action)
            ctx.log("planner", "decision", chosen.name, reason=why)
            ordered.append(chosen)
            pending.remove(chosen)
        with ctx.lock:
            ctx.result.stats["planner"] = stats
        return ordered + pending
