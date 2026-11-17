"""Test dell'orchestratore: ordine, requisiti, errori isolati, timeout, annullamento,
pianificatore LLM con ricorso all'ordine fisso. Nessuna rete."""

import threading
import time

import pytest

from tests.helpers import FAST, make_ctx
from wpsec.agents.base import BaseAgent
from wpsec.core.context import AgentWriteRejected
from wpsec.core.models import AgentState, Confidence, FindingStatus
from wpsec.core.orchestrator import Orchestrator, OrchestratorConfigError, topological_order
from wpsec.scanner.http_client import Cancelled
from wpsec.scanner.wordpress_checks import CheckOutcome

URL = "http://127.0.0.1:9"  # nessuna richiesta viene inviata in questi test


class A(BaseAgent):
    def __init__(self, name, phase="check", depends_on=(), requires=(), fn=None, skip=None):
        self.name, self.display_name, self.description = name, name.upper(), f"agente {name}"
        self.phase, self.depends_on, self.requires = phase, depends_on, requires
        self.fn, self.skip = fn, skip
        self.calls = 0

    def should_run(self, ctx):
        return (False, self.skip) if self.skip else (True, "")

    def run(self, ctx):
        self.calls += 1
        ctx.shared.setdefault("order", []).append(self.name)
        return self.fn(ctx) if self.fn else f"{self.name} ok"


def _states(ctx):
    return {a.name: a.state for a in ctx.result.agents}


# ------------------------------------------------------------ grafo

def test_ordine_topologico_e_fasi():
    agents = [A("report", "analysis", depends_on=("val",)), A("val", "analysis", depends_on=("wp",)),
              A("wp", depends_on=("recon",)), A("recon", "recon")]
    assert [a.name for a in topological_order(agents)] == ["recon", "wp", "val", "report"]


def test_ciclo_rifiutato():
    with pytest.raises(OrchestratorConfigError, match="circolari"):
        topological_order([A("a", depends_on=("b",)), A("b", depends_on=("a",))])


def test_dipendenza_sconosciuta_rifiutata():
    with pytest.raises(OrchestratorConfigError, match="sconosciuto"):
        topological_order([A("a", depends_on=("zzz",))])


def test_nome_duplicato_rifiutato():
    with pytest.raises(OrchestratorConfigError):
        topological_order([A("a"), A("a")])


def test_dipendenza_da_fase_successiva_rifiutata():
    with pytest.raises(OrchestratorConfigError, match="fase successiva"):
        topological_order([A("r", "recon", depends_on=("c",)), A("c")])


# ------------------------------------------------------------ esecuzione

def test_errore_isolato_e_requisito_saltato():
    def boom(ctx):
        raise RuntimeError("target non raggiungibile")
    recon = A("recon", "recon", fn=boom)
    wp = A("wp", depends_on=("recon",), requires=("recon",))
    val = A("val", "analysis", depends_on=("wp",))
    ctx = make_ctx(URL)
    Orchestrator(ctx, [recon, wp, val]).run()
    st = _states(ctx)
    assert st == {"recon": AgentState.FAILED, "wp": AgentState.SKIPPED, "val": AgentState.COMPLETED}
    assert wp.calls == 0
    run = next(a for a in ctx.result.agents if a.name == "recon")
    assert "RuntimeError" in run.error
    events = [e.event for e in ctx.result.trace]
    assert "agent_failed" in events and "agent_skipped" in events


def test_should_run_falso_salta_con_motivo():
    ctx = make_ctx(URL)
    Orchestrator(ctx, [A("wp", skip="WordPress non rilevato")]).run()
    run = ctx.result.agents[0]
    assert run.state == AgentState.SKIPPED and "WordPress" in run.message


def test_timeout_chiude_la_scrittura_dell_agente():
    rilascia = threading.Event()
    esito = {}

    def lento(ctx):
        rilascia.wait(5)
        try:
            ctx.add_finding("wp.xmlrpc", CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.HIGH,
                                                      "tardi"), "slow")
        except AgentWriteRejected as e:
            esito["rifiutato"] = str(e)
        return "fine"

    settings = FAST.with_overrides(agent_timeout=0.2)
    ctx = make_ctx(URL, settings=settings)
    t0 = time.monotonic()
    Orchestrator(ctx, [A("slow", fn=lento), A("dopo")]).run()
    assert time.monotonic() - t0 < 3
    st = _states(ctx)
    assert st["slow"] == AgentState.FAILED and st["dopo"] == AgentState.COMPLETED
    rilascia.set()
    time.sleep(0.3)
    assert "rifiutato" in esito
    assert ctx.get("wp.xmlrpc") is None


def test_annullamento_ferma_la_scansione():
    def annulla(ctx):
        ctx.client.cancel_event.set()
        ctx.client.check_cancelled()
    ctx = make_ctx(URL)
    altro = A("altro", "analysis")
    with pytest.raises(Cancelled):
        Orchestrator(ctx, [A("c", fn=annulla), altro]).run()
    assert altro.calls == 0
    assert _states(ctx)["c"] == AgentState.FAILED


def test_conteggi_dell_agente():
    def trova(ctx):
        ctx.add_finding("wp.xmlrpc", CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.HIGH,
                                                  "ok"), "c")
        return "fatto"
    ctx = make_ctx(URL)
    Orchestrator(ctx, [A("c", fn=trova)]).run()
    run = ctx.result.agents[0]
    assert run.findings == 1 and run.requests == 0 and run.message == "fatto"
    assert run.duration_s >= 0 and run.finished_at is not None


def test_on_update_con_errore_non_ferma():
    def rotto(ctx):
        raise ValueError("ui")
    ctx = make_ctx(URL)
    Orchestrator(ctx, [A("c")], on_update=rotto).run()
    assert _states(ctx)["c"] == AgentState.COMPLETED


# ------------------------------------------------------------ pianificatore LLM

class FakePlanner:
    model, stats = "finto", {}

    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.menus = []

    def plan(self, menu, summaries, steps_left, seed):
        self.menus.append([n for n, _ in menu])
        d = self.decisions.pop(0) if self.decisions else ("fine", "", None)
        return d


def _llm_ctx(ai):
    ctx = make_ctx(URL)
    ctx.ai = ai
    ctx.result.options.planner = "llm"
    return ctx


def test_pianificatore_llm_sceglie_l_ordine():
    ai = FakePlanner([("b", "prima b", None), ("a", "poi a", None)])
    ctx = _llm_ctx(ai)
    Orchestrator(ctx, [A("r", "recon"), A("a", depends_on=("r",)), A("b", depends_on=("r",))]).run()
    assert ctx.shared["order"] == ["r", "b", "a"]
    assert ctx.result.stats["planner"]["invalid"] == 0


def test_pianificatore_llm_non_puo_saltare_controlli():
    ai = FakePlanner([("fine", "basta così", None)])
    ctx = _llm_ctx(ai)
    Orchestrator(ctx, [A("a"), A("b")]).run()
    assert sorted(ctx.shared["order"]) == ["a", "b"]
    assert any(e.event == "end_refused" for e in ctx.result.trace)


def test_pianificatore_llm_ricorre_all_ordine_fisso():
    ai = FakePlanner([(None, "", "azione non ammessa: login")] * 5)
    ctx = _llm_ctx(ai)
    Orchestrator(ctx, [A("a"), A("b")]).run()
    assert ctx.shared["order"] == ["a", "b"]
    assert ctx.result.stats["planner"]["fallback"] is True
    assert len(ai.menus) == FAST.planner_max_invalid


def test_pianificatore_llm_rispetta_le_dipendenze():
    ai = FakePlanner([("a", "", None), ("b", "", None)])
    ctx = _llm_ctx(ai)
    Orchestrator(ctx, [A("a"), A("b", depends_on=("a",))]).run()
    assert ai.menus[0] == ["a"]  # b non è offerto finché a non è in ordine
