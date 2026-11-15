"""ScanContext: lo spazio condiviso ("blackboard") attraverso cui comunicano gli agenti.

Gli agenti non si chiamano fra loro: leggono e scrivono qui. Il contesto applica
le regole che nessun agente (né l'IA) può aggirare:
  - un controllo può creare risultati solo in stato iniziale (mai CONFIRMED);
  - ogni cambio di stato deve essere ammesso da ALLOWED_TRANSITIONS;
  - CONFIRMED richiede evidenze registrate e senza errori;
  - da INCONCLUSIVE si esce solo con una NUOVA evidenza (ricontrollo);
  - le evidenze si aggiungono e non si modificano (tranne l'estratto, impostato una volta);
  - un agente scaduto per timeout non può più scrivere.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from wpsec.ai.prompts import sanitize
from wpsec.config.settings import Settings
from wpsec.core.models import (ALLOWED_TRANSITIONS, Confidence, Evidence, Finding, FindingStatus,
                               ScanResult, StatusChange, TraceEvent)
from wpsec.knowledge.catalog import get_definition

INITIAL_STATUSES = {FindingStatus.CANDIDATE, FindingStatus.NOT_DETECTED, FindingStatus.INCONCLUSIVE,
                    FindingStatus.NOT_APPLICABLE, FindingStatus.ERROR, FindingStatus.INFO}


class TransitionError(Exception):
    """Cambio di stato non ammesso dalle regole."""


class AgentWriteRejected(Exception):
    """Un agente non più attivo (es. scaduto) ha tentato di scrivere."""


class ScanContext:
    def __init__(self, result: ScanResult, settings: Settings, client=None, ai=None, planner=None):
        self.result = result
        self.settings = settings
        self.client = client
        self.ai = ai
        self.planner = planner
        self.lock = threading.RLock()
        self.shared: dict[str, Any] = {}       # dati di lavoro fra agenti (non serializzati)
        self.rechecks: dict[str, Callable[[], tuple]] = {}
        self._evidence: dict[str, Evidence] = {}
        self._by_check: dict[str, Finding] = {}
        self._writers_closed: set[str] = set()
        if client is not None:
            client.on_evidence = self.register_evidence

    # ------------------------------------------------------------ traccia
    def log(self, actor: str, event: str, detail: str = "", **data):
        with self.lock:
            self.result.trace.append(TraceEvent(actor=actor, event=event, detail=detail[:500],
                                                data=data))

    def close_writer(self, agent: str):
        with self.lock:
            self._writers_closed.add(agent)

    def _check_writer(self, agent: str):
        if agent in self._writers_closed:
            raise AgentWriteRejected(f"l'agente {agent} non è più attivo")

    # ------------------------------------------------------------ evidenze
    def register_evidence(self, ev: Evidence):
        with self.lock:
            if ev.id not in self._evidence:
                self._evidence[ev.id] = ev
                self.result.evidence.append(ev)

    def set_excerpt(self, evidence_id: str, text: str):
        """Estratto minimo scelto dall'agente (già minimizzato), impostabile una sola volta."""
        with self.lock:
            ev = self._evidence.get(evidence_id)
            if ev is not None and not ev.excerpt:
                ev.excerpt = sanitize(text, 300)

    def evidence(self, evidence_id: str) -> Evidence | None:
        return self._evidence.get(evidence_id)

    # ------------------------------------------------------------ risultati
    @property
    def findings(self) -> list[Finding]:
        with self.lock:
            return list(self.result.findings)

    def get(self, check_id: str) -> Finding | None:
        return self._by_check.get(check_id)

    def add_finding(self, check_id: str, outcome, agent: str, evidence_ids: list[str] = (),
                    path: str = "/", title: str | None = None,
                    recheck: Callable[[], tuple] | None = None) -> Finding | None:
        """Registra il risultato di un controllo. Ritorna None se il controllo era già
        stato registrato (nessuna esecuzione duplicata)."""
        if outcome.status not in INITIAL_STATUSES:
            raise TransitionError(f"stato iniziale non ammesso: {outcome.status.value}")
        d = get_definition(check_id)
        with self.lock:
            self._check_writer(agent)
            if check_id in self._by_check:
                self.log(agent, "duplicate_ignored", f"controllo {check_id} già registrato")
                return None
            ev_ids = [e for e in evidence_ids if e]
            if outcome.excerpt and ev_ids:
                self.set_excerpt(ev_ids[-1], outcome.excerpt)
            f = Finding(check_id=check_id, legacy_id=d.legacy_id, title=title or d.title,
                        category=d.category, kind=d.kind, status=outcome.status,
                        confidence=outcome.confidence, path=path, summary=outcome.summary,
                        details=dict(outcome.details), evidence_ids=ev_ids, agent=agent)
            f.history.append(StatusChange(from_status=None, to_status=outcome.status, agent=agent,
                                          reason="esito del controllo", evidence_ids=ev_ids))
            self.result.findings.append(f)
            self._by_check[check_id] = f
            if recheck is not None:
                self.rechecks[check_id] = recheck
            self.log(agent, "finding", f"{check_id}: {outcome.status.value}",
                     confidence=outcome.confidence.value)
            return f

    def transition(self, finding: Finding, to: FindingStatus, agent: str, reason: str,
                   evidence_ids: list[str] = (), confidence: Confidence | None = None):
        with self.lock:
            self._check_writer(agent)
            frm = finding.status
            if to not in ALLOWED_TRANSITIONS.get(frm, set()):
                raise TransitionError(f"{finding.check_id}: {frm.value} -> {to.value} non ammessa")
            new_ids = [e for e in evidence_ids if e]
            unknown = [e for e in new_ids if e not in self._evidence]
            if unknown:
                raise TransitionError(f"evidenze sconosciute: {unknown}")
            if to == FindingStatus.CONFIRMED:
                all_ids = finding.evidence_ids + new_ids
                valid = [e for e in all_ids if e in self._evidence and not self._evidence[e].error]
                if not valid:
                    raise TransitionError(f"{finding.check_id}: conferma senza evidenze valide")
            if frm == FindingStatus.INCONCLUSIVE and not any(
                    self._evidence[e].recheck for e in new_ids):
                raise TransitionError(f"{finding.check_id}: da INCONCLUSIVE serve una nuova "
                                      "evidenza di ricontrollo")
            finding.status = to
            if confidence is not None:
                finding.confidence = confidence
            finding.evidence_ids += [e for e in new_ids if e not in finding.evidence_ids]
            finding.history.append(StatusChange(from_status=frm, to_status=to, agent=agent,
                                                reason=reason[:300], evidence_ids=new_ids))
            self.log(agent, "transition", f"{finding.check_id}: {frm.value} -> {to.value}",
                     reason=reason[:200])

    # ------------------------------------------------------------ istantanea
    def snapshot(self) -> ScanResult:
        """Copia coerente del risultato (per l'interfaccia, mentre la scansione è in corso)."""
        with self.lock:
            snap = self.result.model_copy(deep=True)
        if snap.status == "running":
            snap.duration_s = round(time.time() - snap.started_at.timestamp(), 2)
        return snap
