"""Confronto prima/dopo fra due scansioni dello stesso sito.

Differenza principale rispetto a confronta.py (v3): un controllo è "risolto" solo se
PRIMA era confermato e DOPO l'assenza è verificata. Un esito inconcludente (es. blocco
del WAF), un errore o un controllo non applicabile rendono la riga NON CONFRONTABILE:
nella v3 un 403 del WAF dopo le correzioni veniva contato come "risolto".

Si possono confrontare due scansioni v4 (per check_id) oppure una v3 importata con una
v4 (per legacy_id: i sei header della v4 vengono aggregati nel risultato unico "header"
della v3).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from wpsec.core.models import Finding, FindingStatus, ScanResult, Severity

S = FindingStatus
UNCLEAR = {S.INCONCLUSIVE, S.ERROR, S.CANDIDATE, S.NOT_DETECTED}


class ComparisonError(ValueError):
    pass


class Outcome(str, Enum):
    RESOLVED = "resolved"
    STILL_OPEN = "still_open"
    NEW = "new"
    UNCHANGED = "unchanged"
    NOT_COMPARABLE = "not_comparable"
    INFO = "info"

    @property
    def label_it(self) -> str:
        return {"resolved": "RISOLTO", "still_open": "ANCORA APERTO", "new": "NUOVO PROBLEMA",
                "unchanged": "INVARIATO", "not_comparable": "NON CONFRONTABILE",
                "info": "INFO"}[self.value]


class ComparisonRow(BaseModel):
    key: str
    title: str
    before: S | None
    after: S | None
    outcome: Outcome
    reason: str = ""
    severity_before: Severity | None = None
    severity_after: Severity | None = None
    evidence_after: str = ""


class Comparison(BaseModel):
    host: str
    before_id: str
    after_id: str
    before_date: str
    after_date: str
    before_label: str = ""
    after_label: str = ""
    mode: str                      # "v4" | "legacy"
    warnings: list[str] = Field(default_factory=list)
    rows: list[ComparisonRow] = Field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = {o.value: 0 for o in Outcome}
        for r in self.rows:
            c[r.outcome.value] += 1
        return c


def _aggregate(findings: list[Finding]) -> tuple[S, Severity | None, str]:
    """Stato complessivo di un gruppo (es. i sei header v4 contro 'header' della v3)."""
    statuses = {f.status for f in findings}
    conf = [f for f in findings if f.status == S.CONFIRMED]
    if conf:
        sev = min((f.severity for f in conf if f.severity), key=lambda s: s.rank, default=None)
        return S.CONFIRMED, sev, "; ".join(f.summary for f in conf)[:400]
    if statuses & UNCLEAR:
        return S.INCONCLUSIVE, None, "; ".join(f.summary for f in findings if f.status in UNCLEAR)[:400]
    meaningful = statuses - {S.NOT_APPLICABLE}
    if not meaningful:
        return S.NOT_APPLICABLE, None, findings[0].summary[:400]
    if meaningful == {S.INFO}:
        return S.INFO, None, findings[0].summary[:400]
    return S.NOT_PRESENT, None, "; ".join(f.summary for f in findings)[:400]


def _groups(result: ScanResult, by_legacy: bool) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {}
    for f in result.findings:
        key = (f.legacy_id or "") if by_legacy else f.check_id
        if key:
            out.setdefault(key, []).append(f)
    return out


def classify(before: S | None, after: S | None) -> tuple[Outcome, str]:
    if S.INFO in (before, after):
        return Outcome.INFO, "solo contesto"
    if before == after == S.NOT_APPLICABLE:
        return Outcome.INFO, "non applicabile in entrambe"
    if before is None or after is None:
        return Outcome.NOT_COMPARABLE, "controllo presente in una sola delle due scansioni"
    for side, st in (("prima", before), ("dopo", after)):
        if st in UNCLEAR:
            return Outcome.NOT_COMPARABLE, f"esito {side} non netto ({st.value}): verificare manualmente"
        if st == S.NOT_APPLICABLE:
            return Outcome.NOT_COMPARABLE, f"controllo non applicabile {side}"
    b = S.NOT_PRESENT if before == S.FALSE_POSITIVE else before
    a = S.NOT_PRESENT if after == S.FALSE_POSITIVE else after
    if b == S.CONFIRMED and a == S.NOT_PRESENT:
        return Outcome.RESOLVED, "confermato prima, assenza verificata dopo"
    if b == S.NOT_PRESENT and a == S.CONFIRMED:
        return Outcome.NEW, "assente prima, confermato dopo"
    if b == a == S.CONFIRMED:
        return Outcome.STILL_OPEN, "confermato in entrambe"
    return Outcome.UNCHANGED, "assente in entrambe"


def compare(before: ScanResult, after: ScanResult) -> Comparison:
    if before.host != after.host:
        raise ComparisonError(f"host diversi: {before.host} / {after.host}")
    if before.id == after.id:
        raise ComparisonError("si sta confrontando una scansione con sé stessa")
    if before.started_at > after.started_at:
        before, after = after, before
    legacy = "legacy-v3" in (before.source, after.source)
    warnings: list[str] = []
    if legacy:
        warnings.append("Una delle scansioni è della v3: i suoi esiti non erano validati da "
                        "evidenze (es. blocchi del WAF letti come 'protetto'). Il confronto è "
                        "per controllo della v3; i controlli nuovi della v4 non sono confrontati.")
    elif before.catalog_version != after.catalog_version:
        warnings.append(f"Versioni del catalogo diverse ({before.catalog_version} / "
                        f"{after.catalog_version}): gravità e controlli potrebbero differire.")
    for r, side in ((before, "prima"), (after, "dopo")):
        if r.status != "completed":
            warnings.append(f"La scansione {side} non è completata (stato: {r.status}).")
    gb, ga = _groups(before, legacy), _groups(after, legacy)
    keys = list(gb) + [k for k in ga if k not in gb]
    if legacy:  # solo i controlli che la v3 conosceva
        legacy_side = gb if before.source == "legacy-v3" else ga
        keys = [k for k in keys if k in legacy_side]
    rows = []
    for k in keys:
        b = _aggregate(gb[k]) if k in gb else (None, None, "")
        a = _aggregate(ga[k]) if k in ga else (None, None, "")
        outcome, reason = classify(b[0], a[0])
        if outcome == Outcome.STILL_OPEN and b[1] and a[1] and b[1] != a[1]:
            reason += f" (gravità {b[1].label_it} -> {a[1].label_it})"
        title = (ga.get(k) or gb[k])[0].title
        if legacy and k == "header":
            title = "Header di sicurezza HTTP (aggregato)"
        rows.append(ComparisonRow(key=k, title=title, before=b[0], after=a[0], outcome=outcome,
                                  reason=reason, severity_before=b[1], severity_after=a[1],
                                  evidence_after=a[2]))
    return Comparison(host=after.host, before_id=before.id, after_id=after.id,
                      before_date=before.started_at.isoformat(timespec="seconds"),
                      after_date=after.started_at.isoformat(timespec="seconds"),
                      before_label=before.options.label, after_label=after.options.label,
                      mode="legacy" if legacy else "v4", warnings=warnings, rows=rows)


def to_markdown(c: Comparison, anonymize: bool = False) -> str:
    from wpsec.reports.common import md_escape
    host = "(sito anonimizzato)" if anonymize else c.host
    lab = lambda x: f" ({md_escape(x)})" if x else ""  # noqa: E731
    out = [f"# Confronto prima/dopo: {md_escape(host)}", "",
           f"- Prima: {c.before_date}{lab(c.before_label)} — `{c.before_id}`",
           f"- Dopo: {c.after_date}{lab(c.after_label)} — `{c.after_id}`", ""]
    out += [f"> **Attenzione:** {md_escape(w)}" for w in c.warnings]
    out += ["", "| Controllo | Prima | Dopo | Esito | Motivo |", "|---|---|---|---|---|"]
    for r in c.rows:
        out.append(f"| {md_escape(r.title)} | {r.before.value if r.before else '-'} | "
                   f"{r.after.value if r.after else '-'} | **{r.outcome.label_it}** | "
                   f"{md_escape(r.reason)} |")
    n = c.counts()
    out += ["", f"**Sintesi:** {n['resolved']} risolti, {n['still_open']} ancora aperti, "
                f"{n['new']} nuovi problemi, {n['not_comparable']} non confrontabili."]
    if n["info"]:
        out.append("I controlli INFO (contesto, es. WAF) non sono conteggiati.")
    return "\n".join(out) + "\n"
