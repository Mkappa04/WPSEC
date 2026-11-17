"""Report PDF (fpdf2). Usa DejaVu se installato (Unicode completo), altrimenti i font
di base con traslitterazione in Latin-1. Il testo è inserito come testo semplice:
nessuna interpretazione di markup proveniente dal sito."""

from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

from wpsec.reports.common import KIND_IT, STATUS_IT, ReportView

FONT_DIRS = [Path("/usr/share/fonts/truetype/dejavu"), Path("/usr/share/fonts/dejavu"),
             Path("C:/Windows/Fonts")]
_LATIN1 = {"—": "-", "–": "-", "→": "->", "…": "...", "’": "'", "‘": "'", "“": '"', "”": '"',
           "•": "-", "·": "-", "≥": ">=", "≤": "<="}
SEV_RGB = {"critical": (142, 27, 27), "high": (194, 65, 12), "medium": (161, 98, 7),
           "low": (37, 99, 235), "info": (107, 114, 128)}


def _find_font() -> tuple[Path, Path, Path] | None:
    for d in FONT_DIRS:
        reg, bold, mono = d / "DejaVuSans.ttf", d / "DejaVuSans-Bold.ttf", d / "DejaVuSansMono.ttf"
        if reg.exists() and bold.exists() and mono.exists():
            return reg, bold, mono
    return None


class _PDF(FPDF):
    def __init__(self, title: str):
        super().__init__(format="A4")
        self.report_title = title
        self.unicode = False
        fonts = _find_font()
        if fonts:
            self.add_font("body", "", str(fonts[0]))
            self.add_font("body", "B", str(fonts[1]))
            self.add_font("mono", "", str(fonts[2]))
            self.unicode = True
        self.body_font = "body" if self.unicode else "helvetica"
        self.mono_font = "mono" if self.unicode else "courier"
        self.set_auto_page_break(True, margin=15)
        self.set_margins(15, 15, 15)

    def t(self, text) -> str:
        s = str(text or "")
        if self.unicode:
            return s
        for k, val in _LATIN1.items():
            s = s.replace(k, val)
        return s.encode("latin-1", "replace").decode("latin-1")

    def footer(self):
        self.set_y(-12)
        self.set_font(self.body_font, "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, self.t(f"{self.report_title} — pagina {self.page_no()}"), align="C")
        self.set_text_color(0, 0, 0)

    # ------------------------------------------------------------ primitive
    def h1(self, text):
        self.set_font(self.body_font, "B", 16)
        self.multi_cell(0, 8, self.t(text), new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def h2(self, text):
        self.ln(4)
        self.set_font(self.body_font, "B", 13)
        self.multi_cell(0, 7, self.t(text), new_x="LMARGIN", new_y="NEXT")
        y = self.get_y()
        self.set_draw_color(200, 200, 200)
        self.line(self.l_margin, y, self.w - self.r_margin, y)
        self.ln(2)

    def h3(self, text, rgb=(0, 0, 0)):
        self.ln(2)
        self.set_font(self.body_font, "B", 11)
        self.set_text_color(*rgb)
        self.multi_cell(0, 6, self.t(text), new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)

    def p(self, text, size=10, bold=False, color=(0, 0, 0)):
        self.set_font(self.body_font, "B" if bold else "", size)
        self.set_text_color(*color)
        self.multi_cell(0, 5, self.t(text), new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)

    def kv(self, key, value):
        self.set_font(self.body_font, "B", 9)
        self.multi_cell(0, 5, self.t(f"{key}: ") + self.t(value), new_x="LMARGIN", new_y="NEXT")

    def code(self, text):
        self.set_font(self.mono_font, "", 8)
        self.set_fill_color(238, 240, 243)
        self.multi_cell(0, 4, self.t(text), fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def bullet(self, text, size=9):
        self.set_font(self.body_font, "", size)
        self.multi_cell(0, 5, self.t("- " + str(text)), new_x="LMARGIN", new_y="NEXT")


def render_pdf(v: ReportView) -> bytes:
    r, a = v.result, v.a
    pdf = _PDF(v.title)
    pdf.add_page()
    pdf.h1(v.title)
    for k, val in v.meta():
        pdf.kv(k, val)

    pdf.h2("Sintesi")
    if r.executive_summary:
        if r.executive_summary_ai:
            pdf.p(f"[Testo generato dall'IA locale ({r.model_used}) dai soli dati della scansione]",
                  8, color=(109, 40, 217))
        pdf.p(a(r.executive_summary))
    pdf.p("Confermati per gravità: " + (", ".join(f"{s.label_it}: {n}" for s, n in v.severity_counts()
                                                    if n) or "nessuno"), 9, bold=True)
    pdf.p("Esiti: " + ", ".join(f"{k}: {n}" for k, n in v.status_counts()), 9)

    if v.limitations():
        pdf.h2("Limiti dell'analisi")
        for x in v.limitations():
            pdf.bullet(x)

    pdf.h2("Problemi confermati")
    if not v.confirmed:
        pdf.p("Nessun problema confermato con i controlli eseguiti.")
    for i, f in enumerate(v.confirmed, 1):
        sev = f.severity.value if f.severity else "info"
        pdf.h3(f"{i}. {f.title} — {f.severity.label_it if f.severity else '?'} ({f.priority or '-'})",
               SEV_RGB[sev])
        for k, val in (("Tipo", KIND_IT.get(f.kind.value, f.kind.value)), ("Percorso", a(f.path)),
                       ("Evidenza", a(f.summary)), ("CWE", f.cwe), ("CVSS", f.cvss_vector),
                       ("Impatto", f.impact), ("Probabilità", f.likelihood),
                       ("Motivazione", f.rationale)):
            if val:
                pdf.kv(k, val)
        for n in f.ai_notes:
            prio = f" (priorità suggerita: {n.suggested_priority})" if n.suggested_priority else ""
            pdf.p(f"[IA {n.model}, {n.purpose}]{prio} {a(n.text)}", 9, color=(109, 40, 217))
        rem = f.remediation
        if rem:
            pdf.p(f"Correzione: {rem.title} — {rem.summary}", 9, bold=True)
            for label, text in (("WordPress", rem.wordpress), ("Apache", rem.apache),
                                ("Nginx", rem.nginx)):
                if text:
                    pdf.p(label, 8, bold=True)
                    pdf.code(text)
            if rem.risks:
                pdf.kv("Rischi", rem.risks)
            if rem.verification:
                pdf.p("Verifica", 8, bold=True)
                pdf.code(rem.verification)
            if rem.ai_context:
                pdf.p(f"[IA] {rem.ai_context}", 9, color=(109, 40, 217))

    for title, items in (("Da verificare manualmente", v.inconclusive),
                         ("Indicazioni scartate (falsi positivi)", v.false_positive),
                         ("Controlli non eseguiti per errore", v.errors),
                         ("Controlli superati", v.not_present),
                         ("Contesto e controlli non applicabili", v.context)):
        if items:
            pdf.h2(title)
            for f in items:
                pdf.bullet(f"{f.title} — {STATUS_IT.get(f.status.value, '')}: {a(f.summary)}")

    pdf.h2("Agenti")
    for ag in r.agents:
        pdf.bullet(f"{ag.display_name}: {ag.state.value}, {ag.duration_s:.2f}s, {ag.requests} "
                   f"richieste — {a(ag.message or ag.error or '')}")

    evs = [ev for ev in r.evidence if not ev.from_cache]
    if evs:
        pdf.h2("Appendice: evidenze")
        pdf.p("Il corpo delle risposte non viene conservato: solo hash SHA-256, lunghezza ed "
              "estratto minimo.", 8)
        for ev in evs:
            pdf.bullet(f"{ev.id} {ev.method} {a(ev.url)} -> {a(ev.error or ev.status_code)} "
                       f"sha256={ev.body_sha256[:16]} {a(ev.excerpt)}", 8)
    return bytes(pdf.output())
