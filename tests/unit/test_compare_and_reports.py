"""Confronto prima/dopo e generazione dei report (escape, IA marcata, anonimizzazione)."""

from datetime import timedelta
from pathlib import Path

import pytest

from tests.helpers import lab_auth
from wpsec import __version__
from wpsec.comparison.compare import ComparisonError, Outcome, classify, compare, to_markdown
from wpsec.core.models import (AINote, Confidence, Evidence, Finding, FindingKind, FindingStatus,
                               RemediationAdvice, ScanOptions, ScanResult, Severity, now_utc)
from wpsec.knowledge.catalog import CATALOG_VERSION
from wpsec.reports import FORMATS, render, write_reports
from wpsec.reports.common import md_escape

S = FindingStatus
URL = "http://wp.lab.test"
ROOT = Path(__file__).resolve().parents[2]
XSS = '<script>alert(1)</script><img src=x onerror=alert(2)>'


def _f(check_id, status, sev=None, legacy_id="", summary="esito", category="wordpress"):
    return Finding(check_id=check_id, legacy_id=legacy_id, title=f"Titolo {check_id}",
                   category=category, kind=FindingKind.MISCONFIGURATION, status=status,
                   severity=sev, confidence=Confidence.HIGH, summary=summary)


def _scan(findings, minutes_ago=0, host_url=URL, source="v4", **kw):
    r = ScanResult(platform_version=__version__, catalog_version=CATALOG_VERSION, target=host_url,
                   host=host_url.split("//")[1], authorization=lab_auth(host_url),
                   options=ScanOptions(**kw), status="completed", source=source,
                   started_at=now_utc() - timedelta(minutes=minutes_ago))
    r.findings.extend(findings)
    return r


# ------------------------------------------------------------ classificazione

@pytest.mark.parametrize("before,after,expected", [
    (S.CONFIRMED, S.NOT_PRESENT, Outcome.RESOLVED),
    (S.CONFIRMED, S.FALSE_POSITIVE, Outcome.RESOLVED),
    (S.NOT_PRESENT, S.CONFIRMED, Outcome.NEW),
    (S.CONFIRMED, S.CONFIRMED, Outcome.STILL_OPEN),
    (S.NOT_PRESENT, S.NOT_PRESENT, Outcome.UNCHANGED),
    # l'errore della v3: un blocco del WAF dopo le correzioni NON è "risolto"
    (S.CONFIRMED, S.INCONCLUSIVE, Outcome.NOT_COMPARABLE),
    (S.CONFIRMED, S.ERROR, Outcome.NOT_COMPARABLE),
    (S.CONFIRMED, S.NOT_APPLICABLE, Outcome.NOT_COMPARABLE),
    (S.NOT_APPLICABLE, S.NOT_APPLICABLE, Outcome.INFO),
    (S.CONFIRMED, None, Outcome.NOT_COMPARABLE),
    (S.INFO, S.INFO, Outcome.INFO),
])
def test_classificazione(before, after, expected):
    assert classify(before, after)[0] == expected


def test_confronto_v4():
    before = _scan([_f("wp.xmlrpc", S.CONFIRMED, Severity.MEDIUM),
                    _f("wp.users_rest", S.CONFIRMED, Severity.MEDIUM),
                    _f("wp.author_enum", S.CONFIRMED, Severity.LOW)], minutes_ago=60)
    after = _scan([_f("wp.xmlrpc", S.NOT_PRESENT), _f("wp.users_rest", S.INCONCLUSIVE),
                   _f("wp.author_enum", S.CONFIRMED, Severity.MEDIUM)])
    c = compare(after, before)  # l'ordine degli argomenti non conta: decide la data
    assert c.before_id == before.id
    out = {r.key: r for r in c.rows}
    assert out["wp.xmlrpc"].outcome == Outcome.RESOLVED
    assert out["wp.users_rest"].outcome == Outcome.NOT_COMPARABLE
    assert "Bassa -> Media" in out["wp.author_enum"].reason
    assert c.counts()["resolved"] == 1


def test_confronto_host_diversi_rifiutato():
    with pytest.raises(ComparisonError):
        compare(_scan([]), _scan([], host_url="http://altro.test"))


def test_confronto_v3_contro_v4_aggrega_gli_header():
    v3 = _scan([_f("legacy.header", S.CONFIRMED, Severity.LOW, legacy_id="header", category="http"),
                _f("wp.xmlrpc", S.CONFIRMED, Severity.MEDIUM, legacy_id="xmlrpc")],
               minutes_ago=60, source="legacy-v3")
    v4 = _scan([_f("http.header.csp", S.NOT_PRESENT, legacy_id="header", category="http"),
                _f("http.header.xfo", S.CONFIRMED, Severity.LOW, legacy_id="header", category="http"),
                _f("wp.xmlrpc", S.NOT_PRESENT, legacy_id="xmlrpc"),
                _f("wp.debug_log", S.CONFIRMED, Severity.MEDIUM)])  # nuovo controllo v4
    c = compare(v3, v4)
    out = {r.key: r for r in c.rows}
    assert c.mode == "legacy" and c.warnings
    assert out["header"].outcome == Outcome.STILL_OPEN
    assert out["xmlrpc"].outcome == Outcome.RESOLVED
    assert "wp.debug_log" not in out and "" not in out


def test_markdown_del_confronto_anonimizzato():
    before = _scan([_f("wp.xmlrpc", S.CONFIRMED, Severity.MEDIUM)], minutes_ago=5)
    after = _scan([_f("wp.xmlrpc", S.NOT_PRESENT, summary=XSS)])
    md = to_markdown(compare(before, after), anonymize=True)
    assert "wp.lab.test" not in md and "RISOLTO" in md


# ------------------------------------------------------------ report

def _report_scan():
    ev = Evidence(probe_id="wp_users_rest", method="GET", url=URL + "/wp-json/wp/v2/users",
                  status_code=200, body_sha256="ab" * 32, excerpt=XSS)
    f = _f("wp.users_rest", S.CONFIRMED, Severity.MEDIUM, summary=f"utenti esposti {XSS}")
    f.priority, f.cwe, f.evidence_ids = "P3", "CWE-200", [ev.id]
    f.ai_notes.append(AINote(agent="risk", model="qwen3.5:4b", purpose="explanation",
                             text=f"Spiegazione {XSS}", suggested_priority="alta"))
    f.remediation = RemediationAdvice(template_id="wp.users_rest", title="Nascondere",
                                      summary="Rimuovere endpoint", wordpress="add_filter('x');",
                                      verification="curl -s https://SITO/", ai_context="contesto IA")
    r = _scan([f, _f("wp.directory_listing", S.FALSE_POSITIVE, summary="soft-404"),
               _f("wp.xmlrpc", S.INCONCLUSIVE, summary="WAF 403")])
    r.evidence.append(ev)
    r.executive_summary, r.executive_summary_ai, r.model_used = "Sintesi della scansione", True, "qwen3.5:4b"
    r.stats["limitations"] = ["Analisi non invasiva su wp.lab.test"]
    r.authorization.authorizer_name = "Maria Bianchi"
    return r


def test_html_senza_markup_eseguibile():
    html = render(_report_scan(), "html").decode()
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html
    assert "default-src 'none'" in html
    assert "IA locale (qwen3.5:4b)" in html and "Spiegazione" in html


def test_markdown_con_escape_e_ia_marcata():
    md = render(_report_scan(), "md").decode()
    assert "<script>" not in md and "\\<script\\>" in md
    assert "[IA — qwen3.5:4b, explanation]" in md.replace("\\[", "[").replace("\\]", "]")
    assert "Da verificare manualmente" in md and "falsi positivi" in md


def test_md_escape_tabelle_e_link():
    assert md_escape("a|b [x](http://e)") == "a\\|b \\[x\\](http://e)"


@pytest.mark.parametrize("fmt", ["md", "html", "pdf"])
def test_report_anonimizzati(fmt):
    data = render(_report_scan(), fmt, anonymize=True)
    if fmt == "pdf":
        assert data.startswith(b"%PDF")
        return
    text = data.decode()
    assert "wp.lab.test" not in text and "Maria Bianchi" not in text
    assert "sito-analizzato.example" in text


def test_pdf_generato():
    pdf = render(_report_scan(), "pdf")
    assert pdf.startswith(b"%PDF") and len(pdf) > 1000


def test_pdf_senza_font_unicode(monkeypatch):
    from wpsec.reports import pdf_report
    monkeypatch.setattr(pdf_report, "_find_font", lambda: None)
    r = _report_scan()
    r.executive_summary = "Sintesi → con caratteri “speciali” … e ✓"
    assert render(r, "pdf").startswith(b"%PDF")


def test_json_completo_e_ricaricabile():
    r = _report_scan()
    assert ScanResult.model_validate_json(render(r, "json")) == r
    with pytest.raises(ValueError):
        render(r, "json", anonymize=True)


def test_formato_sconosciuto():
    with pytest.raises(ValueError):
        render(_report_scan(), "docx")


def test_write_reports(tmp_path):
    r = _report_scan()
    paths = write_reports(r, tmp_path)
    assert set(paths) == set(FORMATS) and all(p.exists() for p in paths.values())
    anon = write_reports(r, tmp_path, anonymize=True)
    assert "json" not in anon and all("-anon" in p.name for p in anon.values())


def test_report_di_una_scansione_v3_importata():
    files = sorted((ROOT / "scansioni").glob("127.0.0.1_*.json"))
    if not files:
        pytest.skip("nessuna scansione v3 di laboratorio")
    from wpsec.database.legacy import import_legacy_scan
    md = render(import_legacy_scan(files[-1]), "md").decode()
    assert "scanner v3 (importato)" in md
