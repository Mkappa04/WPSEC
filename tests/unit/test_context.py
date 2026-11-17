"""Test di ScanContext: le regole che nessun agente né l'IA può aggirare.

Queste regole sono il cuore del principio guida (il codice decide, l'IA spiega):
nessun percorso verso CONFIRMED senza evidenze registrate e senza errori.
"""

import pytest

from wpsec.core.context import AgentWriteRejected, ScanContext, TransitionError
from wpsec.core.models import (Authorization, AuthorizationKind, Confidence, Evidence,
                               FindingStatus, Origin, ScanOptions, ScanResult, now_utc)
from wpsec.scanner.wordpress_checks import CheckOutcome
from datetime import timedelta

S = FindingStatus
AG = "wordpress"


def _ctx():
    auth = Authorization(kind=AuthorizationKind.LAB, target_url="http://127.0.0.1:9",
                         scope=[Origin.from_url("http://127.0.0.1:9")], authorizer_name="Lab",
                         authorizer_role="Tutor", operator="Studente",
                         valid_from=now_utc() - timedelta(hours=1),
                         valid_until=now_utc() + timedelta(hours=1))
    res = ScanResult(platform_version="4.0.0", catalog_version="test",
                     target="http://127.0.0.1:9", host="127.0.0.1",
                     authorization=auth, options=ScanOptions())
    from wpsec.config.settings import Settings
    return ScanContext(res, Settings())


def _ev(ctx, error=None, recheck=False, probe="wp_users_rest"):
    ev = Evidence(probe_id=probe, method="GET", url="http://127.0.0.1:9/", status_code=200,
                  error=error, recheck=recheck)
    ctx.register_evidence(ev)
    return ev.id


def _candidate(ctx, check_id="wp.users_rest", ev_ids=()):
    out = CheckOutcome(S.CANDIDATE, Confidence.HIGH, "candidato", excerpt="estratto")
    return ctx.add_finding(check_id, out, AG, evidence_ids=list(ev_ids))


# ------------------------------------------------------------ add_finding

def test_add_finding_rifiuta_stato_non_iniziale():
    ctx = _ctx()
    out = CheckOutcome(S.CONFIRMED, Confidence.HIGH, "non ammesso")
    with pytest.raises(TransitionError):
        ctx.add_finding("wp.users_rest", out, AG)


def test_add_finding_duplicato_ignorato():
    ctx = _ctx()
    assert _candidate(ctx) is not None
    assert _candidate(ctx) is None  # secondo controllo stesso check_id -> None
    assert len(ctx.findings) == 1


def test_add_finding_imposta_excerpt_sull_ultima_evidenza():
    ctx = _ctx()
    ev = _ev(ctx)
    _candidate(ctx, ev_ids=[ev])
    assert ctx.evidence(ev).excerpt == "estratto"


# ------------------------------------------------------------ transition verso CONFIRMED

def test_confirmed_richiede_evidenza_valida():
    ctx = _ctx()
    ev = _ev(ctx)
    f = _candidate(ctx, ev_ids=[ev])
    ctx.transition(f, S.CONFIRMED, "evidence", "confermato dalle evidenze")
    assert f.status is S.CONFIRMED


def test_confirmed_senza_evidenze_rifiutato():
    ctx = _ctx()
    f = _candidate(ctx)  # nessuna evidenza
    with pytest.raises(TransitionError):
        ctx.transition(f, S.CONFIRMED, "evidence", "senza prove")


def test_confirmed_con_sola_evidenza_in_errore_rifiutato():
    ctx = _ctx()
    ev = _ev(ctx, error="timeout")
    f = _candidate(ctx, ev_ids=[ev])
    with pytest.raises(TransitionError):
        ctx.transition(f, S.CONFIRMED, "evidence", "evidenza in errore")


def test_transizione_non_ammessa_dal_grafo():
    ctx = _ctx()
    f = _candidate(ctx)
    with pytest.raises(TransitionError):
        ctx.transition(f, S.NOT_PRESENT, "evidence", "percorso non ammesso da CANDIDATE")


def test_transizione_con_evidenza_sconosciuta():
    ctx = _ctx()
    f = _candidate(ctx)
    with pytest.raises(TransitionError):
        ctx.transition(f, S.CONFIRMED, "evidence", "x", evidence_ids=["ev-inesistente"])


# ------------------------------------------------------------ INCONCLUSIVE -> serve ricontrollo

def test_da_inconclusive_serve_evidenza_di_recheck():
    ctx = _ctx()
    out = CheckOutcome(S.INCONCLUSIVE, Confidence.LOW, "incerto")
    f = ctx.add_finding("wp.users_rest", out, AG)
    ev_vecchia = _ev(ctx, recheck=False)
    with pytest.raises(TransitionError):
        ctx.transition(f, S.CONFIRMED, "evidence", "senza ricontrollo", evidence_ids=[ev_vecchia])
    ev_nuova = _ev(ctx, recheck=True)
    ctx.transition(f, S.CONFIRMED, "evidence", "ricontrollo", evidence_ids=[ev_nuova])
    assert f.status is S.CONFIRMED


# ------------------------------------------------------------ writer chiuso

def test_agente_chiuso_non_puo_scrivere():
    ctx = _ctx()
    ctx.close_writer(AG)
    out = CheckOutcome(S.CANDIDATE, Confidence.HIGH, "x")
    with pytest.raises(AgentWriteRejected):
        ctx.add_finding("wp.users_rest", out, AG)


def test_agente_chiuso_non_puo_fare_transizioni():
    ctx = _ctx()
    f = _candidate(ctx)
    ctx.close_writer(AG)
    with pytest.raises(AgentWriteRejected):
        ctx.transition(f, S.FALSE_POSITIVE, AG, "troppo tardi")


# ------------------------------------------------------------ evidenze

def test_register_evidence_idempotente():
    ctx = _ctx()
    ev = Evidence(probe_id="home", method="GET", url="http://x/")
    ctx.register_evidence(ev)
    ctx.register_evidence(ev)
    assert len(ctx.result.evidence) == 1


def test_set_excerpt_una_sola_volta():
    ctx = _ctx()
    ev = _ev(ctx)
    ctx.set_excerpt(ev, "primo")
    ctx.set_excerpt(ev, "secondo")
    assert ctx.evidence(ev).excerpt == "primo"


# ------------------------------------------------------------ snapshot

def test_snapshot_e_copia_profonda():
    ctx = _ctx()
    _candidate(ctx)
    snap = ctx.snapshot()
    snap.findings.clear()
    assert len(ctx.findings) == 1  # lo snapshot non tocca l'originale
