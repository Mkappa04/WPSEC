"""Report in Markdown (leggibile anche come testo, adatto agli allegati della tesi)."""

from __future__ import annotations

import re

from wpsec.reports.common import KIND_IT, STATUS_IT, ReportView, md_escape as e


def _code(text: str) -> list[str]:
    # recinto più lungo di qualunque sequenza di backtick nel testo
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence, text, fence]


def render_markdown(v: ReportView) -> str:
    r, a = v.result, v.a
    out = [f"# {e(v.title)}", ""]
    out += [f"- **{k}:** {e(val)}" for k, val in v.meta()]

    out += ["", "## Sintesi", ""]
    if r.executive_summary:
        if r.executive_summary_ai:
            out.append(f"> *Testo generato dall'IA locale ({e(r.model_used)}) a partire dai soli "
                       "dati della scansione.*")
            out.append("")
        out.append(e(a(r.executive_summary)))
    sev = ", ".join(f"{s.label_it}: {n}" for s, n in v.severity_counts() if n) or "nessuno"
    out += ["", f"**Problemi confermati per gravità:** {sev}", "",
            "**Esiti:** " + ", ".join(f"{k}: {n}" for k, n in v.status_counts())]

    if v.limitations():
        out += ["", "## Limiti dell'analisi", ""] + [f"- {e(x)}" for x in v.limitations()]

    out += ["", "## Problemi confermati", ""]
    if not v.confirmed:
        out.append("Nessun problema confermato con i controlli eseguiti.")
    for i, f in enumerate(v.confirmed, 1):
        out += [f"### {i}. {e(f.title)} — {f.severity.label_it if f.severity else '?'} "
                f"({f.priority or '-'})", "",
                f"- **Tipo:** {KIND_IT.get(f.kind.value, f.kind.value)}",
                f"- **Percorso:** `{e(a(f.path))}`",
                f"- **Evidenza:** {e(a(f.summary))}",
                f"- **Confidenza:** {f.confidence.value}"]
        if f.cwe:
            out.append(f"- **CWE:** {e(f.cwe)}")
        if f.cvss_vector:
            out.append(f"- **CVSS:** `{e(f.cvss_vector)}`")
        if f.impact:
            out.append(f"- **Impatto:** {e(f.impact)}")
        if f.likelihood:
            out.append(f"- **Probabilità:** {e(f.likelihood)}")
        if f.rationale:
            out.append(f"- **Motivazione della gravità:** {e(f.rationale)}")
        for n in f.ai_notes:
            prio = f" (priorità suggerita: {n.suggested_priority})" if n.suggested_priority else ""
            out.append(f"- **[IA — {e(n.model)}, {e(n.purpose)}]** {e(a(n.text))}{prio}")
        rem = f.remediation
        if rem:
            out += ["", f"**Correzione: {e(rem.title)}** — {e(rem.summary)}", ""]
            for label, text in (("WordPress", rem.wordpress), ("Apache", rem.apache),
                                ("Nginx", rem.nginx)):
                if text:
                    out += [f"*{label}:*", ""] + _code(text) + [""]
            if rem.risks:
                out.append(f"*Rischi della correzione:* {e(rem.risks)}")
            if rem.verification:
                out += ["", "*Verifica:*", ""] + _code(rem.verification)
            if rem.ai_context:
                out += ["", f"*[IA] Contesto:* {e(rem.ai_context)}"]
            if rem.references:
                out += ["", "*Riferimenti:* " + ", ".join(e(x) for x in rem.references)]
        out.append("")

    def table(title, findings, note=""):
        if not findings:
            return
        out.extend(["", f"## {title}", ""] + ([note, ""] if note else []))
        out.extend(["| Controllo | Esito | Dettaglio | Motivo |", "|---|---|---|---|"])
        for f in findings:
            out.append(f"| {e(f.title)} | {STATUS_IT.get(f.status.value, f.status.value)} | "
                       f"{e(a(f.summary))[:300]} | {e(v.last_reason(f))[:200]} |")

    table("Da verificare manualmente", v.inconclusive,
          "Le evidenze non permettono di concludere (es. risposta del WAF): il problema "
          "potrebbe esserci o no.")
    table("Indicazioni scartate (falsi positivi)", v.false_positive)
    table("Controlli non eseguiti per errore", v.errors)
    table("Controlli superati", v.not_present)
    table("Contesto e controlli non applicabili", v.context)

    if r.technologies:
        out += ["", "## Tecnologie rilevate", ""]
        out += [f"- **{e(k)}:** {e(a(val))}" for k, val in r.technologies.items()]

    out += ["", "## Agenti", "", "| Agente | Stato | Durata | Richieste | Esito |", "|---|---|---|---|---|"]
    for ag in r.agents:
        out.append(f"| {e(ag.display_name)}{' (IA)' if ag.uses_ai else ''} | {ag.state.value} | "
                   f"{ag.duration_s:.2f}s | {ag.requests} | {e(a(ag.message or ag.error or ''))[:200]} |")

    if r.evidence:
        out += ["", "## Appendice: evidenze", "",
                "Il corpo delle risposte non viene conservato: solo hash SHA-256, lunghezza e un "
                "estratto minimo.", "",
                "| ID | Sonda | Richiesta | Stato | SHA-256 | Estratto |", "|---|---|---|---|---|---|"]
        for ev in r.evidence:
            if ev.from_cache:
                continue
            status = ev.error or str(ev.status_code)
            out.append(f"| `{ev.id}` | {e(ev.probe_id)} | {e(ev.method)} {e(a(ev.url))} | "
                       f"{e(a(status))} | `{ev.body_sha256[:16]}` | {e(a(ev.excerpt))[:160]} |")
    return "\n".join(out) + "\n"
