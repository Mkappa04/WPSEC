"""Report HTML autonomo (un solo file, nessuna risorsa esterna, nessuno script).

Sicurezza: ogni testo passa da html.escape; il file dichiara un CSP che vieta script e
risorse esterne, quindi anche un errore di escape non potrebbe eseguire codice.
"""

from __future__ import annotations

from html import escape

from wpsec.reports.common import KIND_IT, STATUS_IT, ReportView

CSS = """
:root{--bg:#fff;--fg:#1d1f23;--muted:#5d6470;--line:#d9dde3;--card:#f6f7f9;--code:#eef0f3;
--crit:#8e1b1b;--high:#c2410c;--med:#a16207;--low:#2563eb;--info:#6b7280;--ok:#15803d;--ai:#6d28d9}
@media (prefers-color-scheme:dark){:root{--bg:#15171a;--fg:#e6e8eb;--muted:#9aa3ae;--line:#2c3036;
--card:#1d2024;--code:#23272c;--crit:#f87171;--high:#fb923c;--med:#facc15;--low:#60a5fa;--info:#9ca3af;
--ok:#4ade80;--ai:#c4b5fd}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.2rem;margin:36px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{font-size:1.05rem;margin:0 0 8px}.muted{color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;vertical-align:top;
padding:6px 8px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}
.meta td:first-child{width:32%;color:var(--muted)}
.tiles{display:flex;flex-wrap:wrap;gap:8px}.tile{flex:1 1 110px;background:var(--card);border-radius:8px;padding:10px 12px}
.tile b{display:block;font-size:1.5rem}.card{background:var(--card);border-radius:10px;padding:16px;margin:12px 0;
border-left:4px solid var(--info)}
.sev-critical{border-color:var(--crit)}.sev-high{border-color:var(--high)}.sev-medium{border-color:var(--med)}.sev-low{border-color:var(--low)}
.badge{display:inline-block;font-size:.75rem;font-weight:600;padding:1px 8px;border-radius:99px;border:1px solid currentColor}
.b-critical{color:var(--crit)}.b-high{color:var(--high)}.b-medium{color:var(--med)}.b-low{color:var(--low)}.b-info{color:var(--info)}
.ai{border:1px dashed var(--ai);border-radius:8px;padding:8px 10px;margin:8px 0}.ai .tag{color:var(--ai);font-weight:600;font-size:.8rem}
pre{background:var(--code);padding:10px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;font-size:.82rem}
code{font-size:.85em}dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:8px 0}dt{color:var(--muted)}dd{margin:0}
.table-wrap{overflow-x:auto}
@media print{body{background:#fff;color:#000}.card{break-inside:avoid}}
"""


def _sev_badge(f) -> str:
    if not f.severity:
        return ""
    return f'<span class="badge b-{f.severity.value}">{escape(f.severity.label_it)}</span>'


def render_html(v: ReportView) -> str:
    r, a = v.result, v.a
    h: list[str] = []
    w = h.append
    w(f"<h1>{escape(v.title)}</h1>")
    w('<p class="muted">Vulnerability assessment non invasivo — i risultati confermati sono '
      "supportati da evidenze registrate; i contributi dell'IA sono marcati.</p>")
    w('<table class="meta">' + "".join(f"<tr><td>{escape(k)}</td><td>{escape(val)}</td></tr>"
                                       for k, val in v.meta()) + "</table>")

    w("<h2>Sintesi</h2>")
    if r.executive_summary:
        if r.executive_summary_ai:
            w(f'<div class="ai"><div class="tag">IA locale ({escape(r.model_used)}) — basata solo '
              f"sui dati della scansione</div><p>{escape(a(r.executive_summary))}</p></div>")
        else:
            w(f"<p>{escape(a(r.executive_summary))}</p>")
    w('<div class="tiles">' + "".join(
        f'<div class="tile"><b class="b-{s.value}">{n}</b>{escape(s.label_it)}</div>'
        for s, n in v.severity_counts() if s.value != "info") + "</div>")
    w('<p class="muted">' + escape(" · ".join(f"{k}: {n}" for k, n in v.status_counts())) + "</p>")

    if v.limitations():
        w("<h2>Limiti dell'analisi</h2><ul>" +
          "".join(f"<li>{escape(x)}</li>" for x in v.limitations()) + "</ul>")

    w("<h2>Problemi confermati</h2>")
    if not v.confirmed:
        w("<p>Nessun problema confermato con i controlli eseguiti.</p>")
    for i, f in enumerate(v.confirmed, 1):
        sev = f.severity.value if f.severity else "info"
        w(f'<section class="card sev-{sev}"><h3>{i}. {escape(f.title)} {_sev_badge(f)} '
          f'<span class="muted">{escape(f.priority or "")}</span></h3><dl>')
        rows = [("Tipo", KIND_IT.get(f.kind.value, f.kind.value)), ("Percorso", a(f.path)),
                ("Evidenza", a(f.summary)), ("Confidenza", f.confidence.value), ("CWE", f.cwe),
                ("CVSS", f.cvss_vector), ("Impatto", f.impact), ("Probabilità", f.likelihood),
                ("Motivazione", f.rationale)]
        w("".join(f"<dt>{escape(k)}</dt><dd>{escape(val)}</dd>" for k, val in rows if val) + "</dl>")
        evs = v.evidence_for(f)
        if evs:
            w('<p class="muted">Evidenze: ' + ", ".join(
                f"<code>{escape(ev.id)}</code> ({escape(ev.method)} {escape(ev.probe_id)}, "
                f"{escape(ev.error or str(ev.status_code))})" for ev in evs) + "</p>")
        for n in f.ai_notes:
            prio = f" — priorità suggerita: {escape(n.suggested_priority)}" if n.suggested_priority else ""
            w(f'<div class="ai"><div class="tag">IA ({escape(n.model)}, {escape(n.purpose)}){prio}'
              f"</div>{escape(a(n.text))}</div>")
        rem = f.remediation
        if rem:
            w(f"<h3>Correzione: {escape(rem.title)}</h3><p>{escape(rem.summary)}</p>")
            for label, text in (("WordPress", rem.wordpress), ("Apache", rem.apache),
                                ("Nginx", rem.nginx)):
                if text:
                    w(f"<p><b>{label}</b></p><pre>{escape(text)}</pre>")
            if rem.risks:
                w(f"<p><b>Rischi della correzione:</b> {escape(rem.risks)}</p>")
            if rem.verification:
                w(f"<p><b>Verifica</b></p><pre>{escape(rem.verification)}</pre>")
            if rem.ai_context:
                w(f'<div class="ai"><div class="tag">IA — contesto</div>{escape(rem.ai_context)}</div>')
            if rem.references:
                w("<p class='muted'>Riferimenti: " + ", ".join(escape(x) for x in rem.references) + "</p>")
        w("</section>")

    def table(title, findings, note=""):
        if not findings:
            return
        w(f"<h2>{escape(title)}</h2>" + (f"<p class='muted'>{escape(note)}</p>" if note else ""))
        w('<div class="table-wrap"><table><tr><th>Controllo</th><th>Esito</th><th>Dettaglio</th>'
          "<th>Motivo</th></tr>")
        for f in findings:
            w(f"<tr><td>{escape(f.title)}</td><td>{escape(STATUS_IT.get(f.status.value, ''))}</td>"
              f"<td>{escape(a(f.summary))}</td><td>{escape(v.last_reason(f))}</td></tr>")
        w("</table></div>")

    table("Da verificare manualmente", v.inconclusive,
          "Le evidenze non permettono di concludere (es. risposta del WAF): il problema potrebbe "
          "esserci o no.")
    table("Indicazioni scartate (falsi positivi)", v.false_positive)
    table("Controlli non eseguiti per errore", v.errors)
    table("Controlli superati", v.not_present)
    table("Contesto e controlli non applicabili", v.context)

    if r.technologies:
        w("<h2>Tecnologie rilevate</h2><dl>" + "".join(
            f"<dt>{escape(str(k))}</dt><dd>{escape(a(val))}</dd>" for k, val in r.technologies.items())
          + "</dl>")

    w('<h2>Agenti</h2><div class="table-wrap"><table><tr><th>Agente</th><th>Stato</th>'
      "<th>Durata</th><th>Richieste</th><th>Esito</th></tr>")
    for ag in r.agents:
        w(f"<tr><td>{escape(ag.display_name)}{' <span class=badge>IA</span>' if ag.uses_ai else ''}"
          f"</td><td>{escape(ag.state.value)}</td><td>{ag.duration_s:.2f}s</td><td>{ag.requests}</td>"
          f"<td>{escape(a(ag.message or ag.error or ''))}</td></tr>")
    w("</table></div>")

    evs = [ev for ev in r.evidence if not ev.from_cache]
    if evs:
        w("<h2>Appendice: evidenze</h2><p class='muted'>Il corpo delle risposte non viene "
          "conservato: solo hash SHA-256, lunghezza e un estratto minimo.</p>"
          '<div class="table-wrap"><table><tr><th>ID</th><th>Richiesta</th><th>Stato</th>'
          "<th>SHA-256</th><th>Estratto</th></tr>")
        for ev in evs:
            w(f"<tr><td><code>{escape(ev.id)}</code></td><td>{escape(ev.method)} "
              f"{escape(a(ev.url))}</td><td>{escape(a(ev.error or str(ev.status_code)))}</td>"
              f"<td><code>{escape(ev.body_sha256[:16])}</code></td><td>{escape(a(ev.excerpt))}</td></tr>")
        w("</table></div>")

    return ("<!doctype html><html lang=\"it\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
            "style-src 'unsafe-inline'\">"
            f"<title>{escape(v.title)}</title><style>{CSS}</style></head><body><main>"
            + "".join(h) + "</main></body></html>")
