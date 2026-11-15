"""Analisi degli header di sicurezza HTTP (funzioni PURE).

Rispetto alla v3 (un unico risultato "header mancanti"):
  - un risultato per ciascun header, con stato ok / missing / weak / not_applicable;
  - viene valutato anche il VALORE (es. HSTS con max-age basso, CSP con 'unsafe-inline');
  - HSTS su un sito servito in HTTP è "non applicabile" (i browser lo ignorano su HTTP);
  - frame-ancestors nel CSP sostituisce X-Frame-Options (come già nella v3).
Le spiegazioni sono testi scritti a mano: l'IA può solo riformularle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

HSTS_MIN_MAX_AGE = 15_552_000  # 180 giorni


@dataclass
class HeaderAssessment:
    key: str
    header: str
    status: str               # ok | missing | weak | not_applicable
    value: str = ""
    issues: list[str] = field(default_factory=list)
    explanation: str = ""

    @property
    def check_id(self) -> str:
        return f"http.header.{self.key}"


EXPLANATIONS = {
    "hsts": "Strict-Transport-Security obbliga il browser a usare solo HTTPS per il dominio, "
            "impedendo attacchi di downgrade e furto di cookie su reti non fidate.",
    "csp": "Content-Security-Policy limita le origini da cui la pagina può caricare script e "
           "risorse: è la principale mitigazione lato browser contro l'XSS.",
    "xfo": "X-Frame-Options (o frame-ancestors nel CSP) impedisce ad altri siti di incorporare "
           "le pagine in un iframe, mitigando il clickjacking.",
    "xcto": "X-Content-Type-Options: nosniff impedisce al browser di indovinare il tipo dei file "
            "(MIME sniffing), riducendo il rischio che un file caricato venga eseguito come script.",
    "referrer": "Referrer-Policy controlla quanta parte dell'URL viene inviata ad altri siti "
                "nell'header Referer, evitando la fuga di parametri o percorsi interni.",
    "permissions": "Permissions-Policy disattiva le API del browser non usate (fotocamera, "
                   "microfono, geolocalizzazione), riducendo l'impatto di script malevoli.",
}


def _hsts(value: str | None, scheme: str) -> HeaderAssessment:
    a = HeaderAssessment("hsts", "Strict-Transport-Security", "ok", value or "",
                         explanation=EXPLANATIONS["hsts"])
    if scheme != "https":
        a.status = "not_applicable"
        a.issues.append("il sito è analizzato in HTTP: HSTS viene ignorato dai browser su HTTP")
        return a
    if not value:
        a.status = "missing"
        return a
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    if not m:
        a.status, a.issues = "weak", ["max-age assente o non valido"]
    elif int(m.group(1)) < HSTS_MIN_MAX_AGE:
        a.status = "weak"
        a.issues.append(f"max-age={m.group(1)} inferiore a 180 giorni ({HSTS_MIN_MAX_AGE}s)")
    return a


def _csp_directives(value: str) -> dict[str, str]:
    out = {}
    for part in value.split(";"):
        part = part.strip()
        if part:
            name, _, rest = part.partition(" ")
            out[name.lower()] = rest.strip()
    return out


def _csp(value: str | None, report_only: str | None) -> HeaderAssessment:
    a = HeaderAssessment("csp", "Content-Security-Policy", "ok", value or "",
                         explanation=EXPLANATIONS["csp"])
    if not value:
        a.status = "missing"
        if report_only:
            a.issues.append("presente solo Content-Security-Policy-Report-Only (non applicata)")
        return a
    d = _csp_directives(value)
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        a.issues.append("nessuna direttiva script-src o default-src: gli script non sono limitati")
    else:
        if "'unsafe-inline'" in script and "'nonce-" not in script and "'strict-dynamic'" not in script:
            a.issues.append("'unsafe-inline' consente script inline: la protezione dall'XSS è ridotta")
        if "'unsafe-eval'" in script:
            a.issues.append("'unsafe-eval' consente eval()")
        if re.search(r"(^|\s)(\*|https?:|data:)(\s|$)", script):
            a.issues.append("sorgenti troppo ampie per gli script (*, http:, https: o data:)")
    if a.issues:
        a.status = "weak"
    return a


def _xfo(value: str | None, csp: str | None) -> HeaderAssessment:
    a = HeaderAssessment("xfo", "X-Frame-Options", "ok", value or "", explanation=EXPLANATIONS["xfo"])
    if csp and "frame-ancestors" in csp.lower():
        a.issues.append("protezione fornita da frame-ancestors nel CSP")
        return a
    if not value:
        a.status = "missing"
    elif value.strip().upper() not in ("DENY", "SAMEORIGIN"):
        a.status = "weak"
        a.issues.append(f"valore '{value}' non standard o deprecato (ALLOW-FROM non è supportato)")
    return a


def _xcto(value: str | None) -> HeaderAssessment:
    a = HeaderAssessment("xcto", "X-Content-Type-Options", "ok", value or "",
                         explanation=EXPLANATIONS["xcto"])
    if not value:
        a.status = "missing"
    elif value.strip().lower() != "nosniff":
        a.status, a.issues = "weak", [f"valore '{value}' diverso da nosniff"]
    return a


def _referrer(value: str | None) -> HeaderAssessment:
    a = HeaderAssessment("referrer", "Referrer-Policy", "ok", value or "",
                         explanation=EXPLANATIONS["referrer"])
    if not value:
        a.status = "missing"
    else:
        last = value.split(",")[-1].strip().lower()  # vale l'ultimo valore riconosciuto
        if last in ("unsafe-url", "no-referrer-when-downgrade"):
            a.status = "weak"
            a.issues.append(f"'{last}' invia l'URL completo ad altri siti")
    return a


def _permissions(value: str | None) -> HeaderAssessment:
    a = HeaderAssessment("permissions", "Permissions-Policy", "ok", value or "",
                         explanation=EXPLANATIONS["permissions"])
    if not value:
        a.status = "missing"
    return a


def analyze_security_headers(headers: dict[str, str], scheme: str) -> list[HeaderAssessment]:
    h = {k.lower(): v for k, v in headers.items()}
    csp = h.get("content-security-policy")
    return [
        _hsts(h.get("strict-transport-security"), scheme),
        _csp(csp, h.get("content-security-policy-report-only")),
        _xfo(h.get("x-frame-options"), csp),
        _xcto(h.get("x-content-type-options")),
        _referrer(h.get("referrer-policy")),
        _permissions(h.get("permissions-policy")),
    ]


DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                      "x-generator")


def disclosure_headers(headers: dict[str, str]) -> dict[str, str]:
    """Header che rivelano software e versioni. 'Server' senza numeri (es. 'nginx',
    'cloudflare') non viene segnalato: non rivela una versione."""
    out = {}
    for k in DISCLOSURE_HEADERS:
        v = headers.get(k)
        if not v:
            continue
        if k == "server" and not re.search(r"\d", v):
            continue
        out[k] = v[:120]
    return out


@dataclass
class CookieAssessment:
    name: str
    secure: bool
    httponly: bool
    samesite: str


def analyze_cookies(set_cookies: list[str]) -> list[CookieAssessment]:
    out = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = [p.strip().lower() for p in raw.split(";")[1:]]
        samesite = next((p.split("=", 1)[1] for p in attrs if p.startswith("samesite=")), "")
        out.append(CookieAssessment(name, "secure" in attrs, "httponly" in attrs, samesite))
    return out
