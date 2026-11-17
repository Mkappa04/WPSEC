"""Regole dell'Evidence Validation Agent e del Risk Assessment Agent (senza rete)."""

from tests.helpers import make_ctx
from wpsec.agents.evidence_agent import EvidenceValidationAgent
from wpsec.agents.risk_agent import RiskAssessmentAgent, cwe_for, severity_for
from wpsec.core.models import Confidence, Evidence, FindingStatus, Severity
from wpsec.scanner.wordpress_checks import CheckOutcome

S, C = FindingStatus, Confidence
URL = "http://127.0.0.1:9"


def _ctx():
    return make_ctx(URL)


def _ev(ctx, error=None, recheck=False):
    ev = Evidence(probe_id="wp_users_rest", method="GET", url=URL + "/x", status_code=200,
                  error=error, recheck=recheck)
    ctx.register_evidence(ev)
    return ev.id


def _add(ctx, check_id, status, conf=C.HIGH, recheck=None, error=None, **details):
    return ctx.add_finding(check_id, CheckOutcome(status, conf, "esito", details=details), "wordpress",
                           [_ev(ctx, error=error)], recheck=recheck)


def _validate(ctx):
    EvidenceValidationAgent().run(ctx)


# ------------------------------------------------------------ CANDIDATE

def test_candidato_con_evidenza_confermato():
    ctx = _ctx()
    f = _add(ctx, "wp.users_rest", S.CANDIDATE)
    _validate(ctx)
    assert f.status == S.CONFIRMED
    assert f.history[-1].agent == "evidence"


def test_candidato_bloccato_dal_waf_inconcludente():
    ctx = _ctx()
    f = _add(ctx, "wp.users_rest", S.CANDIDATE, waf_block=True, http_status=403)
    _validate(ctx)
    assert f.status == S.INCONCLUSIVE and "WAF" in f.summary


def test_candidato_con_controprova_falso_positivo():
    ctx = _ctx()
    f = _add(ctx, "wp.directory_listing", S.CANDIDATE, C.LOW,
             counter_evidence="pagina generata da WordPress (soft-404)")
    _validate(ctx)
    assert f.status == S.FALSE_POSITIVE


def test_candidato_debole_senza_controprova_inconcludente():
    ctx = _ctx()
    f = _add(ctx, "wp.directory_listing", S.CANDIDATE, C.LOW, counter_evidence="")
    _validate(ctx)
    assert f.status == S.INCONCLUSIVE


def test_candidato_con_sole_evidenze_in_errore_non_confermato():
    ctx = _ctx()
    f = _add(ctx, "wp.users_rest", S.CANDIDATE, error="timeout")
    _validate(ctx)
    assert f.status == S.INCONCLUSIVE
    assert any(e.event == "validation_error" for e in ctx.result.trace)


# ------------------------------------------------------------ NOT_DETECTED

def test_non_rilevato_netto_assente():
    ctx = _ctx()
    f = _add(ctx, "wp.xmlrpc", S.NOT_DETECTED)
    _validate(ctx)
    assert f.status == S.NOT_PRESENT


def test_non_rilevato_dietro_waf_inconcludente():
    ctx = _ctx()
    f = _add(ctx, "wp.users_rest", S.NOT_DETECTED, waf_block=True, http_status=403)
    _validate(ctx)
    assert f.status == S.INCONCLUSIVE


def test_home_bloccata_rende_inconcludenti_i_controlli_wordpress():
    ctx = _ctx()
    ctx.shared["home_blocked"] = True
    f = _add(ctx, "wp.xmlrpc", S.NOT_DETECTED)
    _validate(ctx)
    assert f.status == S.INCONCLUSIVE


def test_errore_temporaneo_risolto_dal_ricontrollo():
    ctx = _ctx()

    def recheck():
        return CheckOutcome(S.NOT_DETECTED, C.HIGH, "ricontrollo: 404"), [_ev(ctx, recheck=True)]

    f = _add(ctx, "wp.debug_log", S.NOT_DETECTED, recheck=recheck, transient=True)
    _validate(ctx)
    assert f.status == S.NOT_PRESENT
    assert [h.to_status for h in f.history] == [S.NOT_DETECTED, S.INCONCLUSIVE, S.NOT_PRESENT]
    assert f.summary == "ricontrollo: 404" and f.details["rechecked"] is True
    assert ctx.result.stats["validation"]["recheck_resolved"] == 1
    assert ctx.result.stats["validation"]["not_present"] == 1
    assert ctx.result.stats["validation"]["inconclusive"] == 0


# ------------------------------------------------------------ ERROR

def test_errore_ricontrollato_e_confermato():
    ctx = _ctx()

    def recheck():
        return CheckOutcome(S.CANDIDATE, C.HIGH, "utenti esposti"), [_ev(ctx, recheck=True)]

    f = _add(ctx, "wp.users_rest", S.ERROR, C.LOW, recheck=recheck, error="timeout")
    _validate(ctx)
    assert [h.to_status for h in f.history] == [S.ERROR, S.INCONCLUSIVE, S.CONFIRMED]


def test_errore_che_persiste_resta_inconcludente():
    ctx = _ctx()

    def recheck():
        return CheckOutcome(S.ERROR, C.LOW, "timeout"), [_ev(ctx, error="timeout", recheck=True)]

    f = _add(ctx, "wp.users_rest", S.ERROR, C.LOW, recheck=recheck, error="timeout")
    _validate(ctx)
    assert f.status == S.INCONCLUSIVE


def test_errore_di_perimetro_non_ricontrollato():
    ctx = _ctx()
    chiamate = []

    def recheck():
        chiamate.append(1)
        return CheckOutcome(S.ERROR, C.LOW, "x"), []

    f = _add(ctx, "wp.users_rest", S.ERROR, C.LOW, recheck=recheck, error="bloccato",
             scope_blocked=True)
    _validate(ctx)
    assert f.status == S.ERROR and not chiamate


def test_info_e_non_applicabile_non_toccati():
    ctx = _ctx()
    a = _add(ctx, "wp.login_page", S.INFO)
    b = _add(ctx, "http.cookies", S.NOT_APPLICABLE)
    _validate(ctx)
    assert a.status == S.INFO and b.status == S.NOT_APPLICABLE


# ------------------------------------------------------------ rischio

def _confirmed(ctx, check_id, **details):
    f = _add(ctx, check_id, S.CANDIDATE, **details)
    ctx.transition(f, S.CONFIRMED, "evidence", "test")
    return f


def test_gravita_xmlrpc_dipende_da_multicall():
    ctx = _ctx()
    con = _confirmed(ctx, "wp.xmlrpc", multicall=True)
    assert severity_for(con)[0] == Severity.MEDIUM
    con.details["multicall"] = False
    assert severity_for(con)[0] == Severity.LOW


def test_cwe_dei_cookie_dall_attributo_mancante():
    ctx = _ctx()
    f = _confirmed(ctx, "http.cookies", cookies={"sess": ["secure", "httponly"], "x": ["samesite"]})
    assert cwe_for(f) == "CWE-614, CWE-1004"


def test_risk_agent_assegna_dal_catalogo_e_correla():
    ctx = _ctx()
    users = _confirmed(ctx, "wp.users_rest")
    xmlrpc = _confirmed(ctx, "wp.xmlrpc", multicall=True)
    absent = _add(ctx, "wp.debug_log", S.NOT_DETECTED)
    RiskAssessmentAgent().run(ctx)
    assert users.severity == Severity.MEDIUM and users.priority == "P3"
    assert users.cwe == "CWE-200" and users.cvss_vector == ""
    assert "XML-RPC" in users.likelihood and "username" in xmlrpc.likelihood
    assert absent.severity is None  # solo i confermati vengono valutati


class StubAI:
    model, stats = "stub", {}

    def explain(self, finding):
        from wpsec.core.models import AINote
        return AINote(agent="risk", model="stub", purpose="explanation",
                      text="Spiegazione di prova.", suggested_priority="alta")


def test_ia_non_cambia_gravita_ne_priorita():
    ctx = _ctx()
    ctx.ai = StubAI()
    f = _confirmed(ctx, "wp.author_enum")
    RiskAssessmentAgent().run(ctx)
    assert f.severity == Severity.LOW and f.priority == "P4"
    assert f.ai_notes and f.ai_notes[0].suggested_priority == "alta"


def test_valutazione_rifiutata_se_non_confermato():
    import pytest
    from wpsec.core.context import TransitionError
    ctx = _ctx()
    f = _add(ctx, "wp.xmlrpc", S.CANDIDATE)
    with pytest.raises(TransitionError):
        ctx.set_assessment(f, "risk", severity=Severity.HIGH)
    with pytest.raises(ValueError):
        ctx.set_assessment(f, "risk", status="confirmed")
