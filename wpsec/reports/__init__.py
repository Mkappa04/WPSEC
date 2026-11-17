"""Generazione dei report (JSON, Markdown, HTML, PDF) da uno ScanResult."""

from __future__ import annotations

from pathlib import Path

from wpsec.core.models import ScanResult
from wpsec.reports.common import ReportView, build_view

FORMATS = ("json", "md", "html", "pdf")


def render(result: ScanResult, fmt: str, anonymize: bool = False) -> bytes:
    if fmt not in FORMATS:
        raise ValueError(f"formato non supportato: {fmt} (ammessi: {', '.join(FORMATS)})")
    if fmt == "json":
        if anonymize:
            raise ValueError("l'esportazione JSON anonimizzata non è supportata: usare md/html/pdf")
        return result.model_dump_json(indent=2).encode("utf-8")
    view = build_view(result, anonymize)
    if fmt == "md":
        from wpsec.reports.markdown import render_markdown
        return render_markdown(view).encode("utf-8")
    if fmt == "html":
        from wpsec.reports.html_report import render_html
        return render_html(view).encode("utf-8")
    from wpsec.reports.pdf_report import render_pdf
    return render_pdf(view)


def write_reports(result: ScanResult, directory: Path | str, formats=FORMATS,
                  anonymize: bool = False) -> dict[str, Path]:
    """Scrive i report in directory/<scan_id>[-anon].<ext>. Ritorna {formato: percorso}."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    out = {}
    for fmt in formats:
        if anonymize and fmt == "json":
            continue
        path = d / f"{result.id}{'-anon' if anonymize else ''}.{fmt}"
        path.write_bytes(render(result, fmt, anonymize))
        out[fmt] = path
    return out


__all__ = ["FORMATS", "ReportView", "build_view", "render", "write_reports"]
