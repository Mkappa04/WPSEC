"""Vista comune dei report: ordina e prepara i dati di uno ScanResult per i vari formati.

Regole valide per tutti i formati:
  - tutto il testo che viene dal sito analizzato è NON ATTENDIBILE: ogni formato lo
    sottopone a escape (HTML, Markdown) prima di inserirlo;
  - i contributi dell'IA sono sempre marcati come tali e separati dai dati deterministici;
  - anonymize=True sostituisce host, nomi di chi ha autorizzato e dell'operatore e il
    riferimento al documento (per la tesi); gli username sono già mascherati alla fonte.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from wpsec.core.models import Finding, FindingStatus, ScanResult, Severity

S = FindingStatus

STATUS_IT = {
    "confirmed": "Confermato", "false_positive": "Falso positivo",
    "not_present": "Non rilevato (verificato)", "inconclusive": "Inconcludente",
    "not_applicable": "Non applicabile", "error": "Errore", "info": "Informativo",
    "candidate": "Da validare", "not_detected": "Da validare",
}
KIND_IT = {"vulnerability": "Vulnerabilità", "misconfiguration": "Configurazione debole",
           "information_exposure": "Esposizione di informazioni", "informational": "Contesto"}
AGENT_STATE_IT = {"pending": "In attesa", "running": "In corso", "completed": "Completato",
                  "failed": "Fallito", "skipped": "Saltato"}
ANON_HOST = "sito-analizzato.example"


def md_escape(text) -> str:
    """Escape per Markdown: neutralizza formattazione, link, HTML e celle di tabella."""
    t = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", str(text or ""))
    t = t.replace("\\", "\\\\")
    for ch in "`*_[]<>|#!":
        t = t.replace(ch, "\\" + ch)
    return t.replace("\n", " ")


class Anonymizer:
    def __init__(self, result: ScanResult, enabled: bool):
        self.enabled = enabled
        a = result.authorization
        self._subs: list[tuple[re.Pattern, str]] = []
        if enabled:
            # host: senza distinzione di maiuscole; nomi: esatti e a parola intera
            self._subs.append((re.compile(re.escape(result.host), re.I), ANON_HOST))
            for value, repl in ((a.authorizer_name, "[autorizzante]"), (a.operator, "[operatore]")):
                if value and len(value) >= 2:
                    self._subs.append((re.compile(rf"\b{re.escape(value)}\b"), repl))

    def __call__(self, text) -> str:
        t = str(text or "")
        for pat, repl in self._subs:
            t = pat.sub(repl, t)
        return t


@dataclass
class ReportView:
    result: ScanResult
    anonymize: bool
    a: Anonymizer
    confirmed: list[Finding] = field(default_factory=list)
    inconclusive: list[Finding] = field(default_factory=list)
    false_positive: list[Finding] = field(default_factory=list)
    errors: list[Finding] = field(default_factory=list)
    not_present: list[Finding] = field(default_factory=list)
    context: list[Finding] = field(default_factory=list)     # info + non applicabili

    @property
    def title(self) -> str:
        return f"Report di sicurezza — {self.host}"

    @property
    def host(self) -> str:
        return self.a(self.result.host)

    def meta(self) -> list[tuple[str, str]]:
        r, au = self.result, self.result.authorization
        rows = [
            ("Target", self.a(r.target)),
            ("Data", r.started_at.strftime("%Y-%m-%d %H:%M UTC")),
            ("Durata", f"{r.duration_s:.1f} s"),
            ("Stato", r.status),
            ("Origine dati", "piattaforma v4" if r.source == "v4" else "scanner v3 (importato)"),
            ("Versione piattaforma / catalogo", f"{r.platform_version} / {r.catalog_version}"),
            ("Autorizzazione", f"{au.id} ({au.kind.value}), valida dal "
                               f"{au.valid_from:%Y-%m-%d} al {au.valid_until:%Y-%m-%d}"),
            ("Autorizzata da", "[anonimizzato]" if self.anonymize
             else f"{au.authorizer_name} ({au.authorizer_role})"),
            ("Operatore", "[anonimizzato]" if self.anonymize else au.operator),
            ("Rete", r.network_mode or "-"),
            ("User-Agent", r.user_agent or "-"),
            ("Modello IA", r.model_used or "nessuno"),
        ]
        if au.document_ref and not self.anonymize:
            rows.insert(8, ("Documento di autorizzazione", au.document_ref))
        if r.options.label:
            rows.insert(2, ("Etichetta", r.options.label))
        if r.error:
            rows.append(("Errore", r.error))
        return rows

    def severity_counts(self) -> list[tuple[Severity, int]]:
        c = self.result.severity_counts()
        return [(s, c[s.value]) for s in Severity]

    def status_counts(self) -> list[tuple[str, int]]:
        c = self.result.counts()
        order = ["confirmed", "inconclusive", "false_positive", "not_present", "error",
                 "not_applicable", "info"]
        return [(STATUS_IT[k], c[k]) for k in order if c.get(k)]

    def limitations(self) -> list[str]:
        return [self.a(x) for x in self.result.stats.get("limitations", [])]

    def evidence_for(self, f: Finding):
        by_id = {e.id: e for e in self.result.evidence}
        return [by_id[i] for i in f.evidence_ids if i in by_id]

    @staticmethod
    def last_reason(f: Finding) -> str:
        return f.history[-1].reason if f.history else ""


def build_view(result: ScanResult, anonymize: bool = False) -> ReportView:
    v = ReportView(result, anonymize, Anonymizer(result, anonymize))
    key = lambda f: (f.severity.rank if f.severity else 9, f.check_id)  # noqa: E731
    for f in sorted(result.findings, key=key):
        {S.CONFIRMED: v.confirmed, S.INCONCLUSIVE: v.inconclusive,
         S.FALSE_POSITIVE: v.false_positive, S.ERROR: v.errors, S.NOT_PRESENT: v.not_present,
         S.CANDIDATE: v.inconclusive, S.NOT_DETECTED: v.inconclusive,
         }.get(f.status, v.context).append(f)
    return v
