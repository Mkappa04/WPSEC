"""Analisi delle risposte per i controlli WordPress (funzioni PURE, senza rete).

Ogni funzione riceve stato HTTP e corpo e restituisce un CheckOutcome con stato
iniziale (CANDIDATE / NOT_DETECTED / ...), confidenza ed estratto minimo.
La decisione finale (confermato, falso positivo, inconcludente) spetta
all'Evidence Validation Agent.

Derivano dai controlli della v3 (Pentest_ollama_v2.py), con queste differenze:
  - utenti: si richiedono oggetti con 'id' e 'slug' (non una lista qualsiasi);
  - versione: meta in qualunque ordine di attributi, feed, readme, ?ver= degli asset;
  - directory listing: firma forte (<title>/<h1> "Index of /") separata dalla semplice
    parola "index of", che da sola genera solo un candidato a bassa confidenza.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from wpsec.core.models import Confidence, FindingStatus

VERSION_RE = r"(\d+\.\d+(?:\.\d+)?)"
WP_PAGE_MARKERS = ("/wp-content/themes/", "/wp-content/plugins/", "/wp-includes/",
                   "https://api.w.org/", "wp-block-")


@dataclass
class CheckOutcome:
    status: FindingStatus
    confidence: Confidence
    summary: str
    excerpt: str = ""
    details: dict[str, Any] = field(default_factory=dict)


def redact_username(name: str) -> str:
    name = str(name)
    if len(name) <= 2:
        return "*" * len(name)
    return name[0] + "*" * (len(name) - 2) + name[-1]


def has_wp_markers(body: str) -> bool:
    return any(m in body for m in WP_PAGE_MARKERS)


# ---------------------------------------------------------------- utenti REST

def parse_rest_users(status: int, body: str) -> list[dict] | None:
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, list):
        return None
    users = [{"id": u.get("id"), "slug": str(u.get("slug"))} for u in data
             if isinstance(u, dict) and "id" in u and u.get("slug")]
    return users or None


def users_outcome(status: int, body: str, path: str, redact: bool) -> CheckOutcome:
    users = parse_rest_users(status, body)
    if users:
        shown = [f"id={u['id']} slug='{redact_username(u['slug']) if redact else u['slug']}'"
                 for u in users]
        return CheckOutcome(
            FindingStatus.CANDIDATE, Confidence.HIGH,
            f"{len(users)} utenti leggibili senza login da {path}: " + "; ".join(shown[:10]),
            excerpt="; ".join(shown[:10]),
            details={"count": len(users), "path": path, "redacted": redact})
    if status in (401, 403, 404):
        return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.HIGH,
                            f"{path}: HTTP {status}, nessun utente leggibile",
                            details={"http_status": status, "path": path})
    if status == 200:
        return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.MEDIUM,
                            f"{path}: HTTP 200 ma nessun elenco di utenti",
                            details={"http_status": status, "path": path})
    return CheckOutcome(FindingStatus.INCONCLUSIVE, Confidence.LOW,
                        f"{path}: risposta inattesa HTTP {status}",
                        details={"http_status": status, "path": path})


# ---------------------------------------------------------------- autori

AUTHOR_URL_RE = re.compile(r"/author/([^/?#]+)/?")


def author_from_urls(urls: list[str]) -> str | None:
    for u in urls:
        m = AUTHOR_URL_RE.search(u or "")
        if m and not m.group(1).isdigit():
            return m.group(1)
    return None


def author_from_body(body: str) -> str | None:
    """Con i permalink semplici non c'è redirect, ma la pagina archivio ha
    nel <body> la classe 'author-<username>' (logica della v3)."""
    m = re.search(r"<body[^>]*\bclass=[\"']([^\"']*)[\"']", body or "", re.I)
    if not m or "author" not in m.group(1).split():
        return None
    for c in m.group(1).split():
        if c.startswith("author-") and c[7:] and not c[7:].isdigit():
            return c[7:]
    return None


def author_outcome(status: int, body: str, redirect_urls: list[str], redact: bool) -> CheckOutcome:
    name = author_from_urls(redirect_urls)
    source = "redirect"
    if not name and status == 200:
        name, source = author_from_body(body), "classe del <body>"
    if name:
        shown = redact_username(name) if redact else name
        return CheckOutcome(FindingStatus.CANDIDATE, Confidence.HIGH,
                            f"?author=1 rivela lo username '{shown}' ({source})",
                            excerpt=f"username={shown}", details={"source": source})
    return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.HIGH if status in (200, 301, 302, 403, 404)
                        else Confidence.LOW,
                        f"Nessun username nel redirect né nella pagina (HTTP {status})",
                        details={"http_status": status})


# ---------------------------------------------------------------- XML-RPC

def xmlrpc_outcome(status: int, body: str) -> CheckOutcome:
    if status == 200 and "<methodResponse" in body and "<fault>" not in body:
        methods = re.findall(r"<string>([\w.]+)</string>", body)
        multicall = "system.multicall" in methods
        return CheckOutcome(
            FindingStatus.CANDIDATE, Confidence.HIGH,
            f"xmlrpc.php risponde e espone {len(methods)} metodi"
            + (" (incluso system.multicall: amplifica il brute force)" if multicall else ""),
            excerpt=", ".join(methods[:8]), details={"methods": len(methods), "multicall": multicall})
    if status == 200 and "<fault>" in body:
        return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.HIGH,
                            "xmlrpc.php raggiungibile ma risponde con <fault>: metodi non esposti",
                            details={"http_status": status, "fault": True})
    if status in (401, 403, 404, 405, 410):
        return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.HIGH,
                            f"Nessuna risposta XML-RPC valida (HTTP {status})",
                            details={"http_status": status})
    return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.MEDIUM,
                        f"Nessuna risposta XML-RPC valida (HTTP {status})",
                        details={"http_status": status})


# ---------------------------------------------------------------- versione

_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR_RE = re.compile(r"(\w[\w-]*)\s*=\s*([\"'])(.*?)\2", re.S)


def version_from_meta(html: str) -> str | None:
    for tag in _META_TAG_RE.findall(html or ""):
        attrs = {k.lower(): v for k, _, v in _ATTR_RE.findall(tag)}
        if attrs.get("name", "").lower() == "generator":
            m = re.match(r"\s*WordPress\s+" + VERSION_RE, attrs.get("content", ""), re.I)
            if m:
                return m.group(1)
    return None


def version_from_feed(xml: str) -> str | None:
    m = re.search(r"<generator>\s*https?://wordpress\.org/\?v=" + VERSION_RE + r"\s*</generator>",
                  xml or "", re.I)
    return m.group(1) if m else None


def version_from_readme(html: str) -> str | None:
    m = re.search(r"<br\s*/?>\s*Version\s+" + VERSION_RE, html or "", re.I)
    return m.group(1) if m else None


def version_from_assets(html: str) -> str | None:
    """?ver= sugli script di wp-includes: spesso coincide con la versione di WordPress,
    ma non sempre (plugin di cache, ottimizzatori): confidenza media."""
    found = re.findall(r"/wp-includes/[^\"'\s>]+\?ver=" + VERSION_RE, html or "")
    if not found:
        return None
    return Counter(found).most_common(1)[0][0]


def version_outcome(sources: dict[str, str | None]) -> CheckOutcome:
    """sources: {'meta': '6.8.1', 'feed': None, 'readme': None, 'assets': '6.8.1'}."""
    found = {k: v for k, v in sources.items() if v}
    if not found:
        return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.MEDIUM,
                            "Nessuna versione di WordPress esposta (meta, feed, readme, asset)",
                            details={"sources_checked": list(sources)})
    strong = {k: v for k, v in found.items() if k in ("meta", "feed", "readme")}
    version = next(iter(strong.values()), None) or found["assets"]
    where = ", ".join(f"{k}={v}" for k, v in found.items())
    return CheckOutcome(
        FindingStatus.CANDIDATE, Confidence.HIGH if strong else Confidence.MEDIUM,
        f"Versione WordPress {version} esposta ({where})", excerpt=where,
        details={"version": version, "sources": found,
                 "conflict": len(set(found.values())) > 1})


# ---------------------------------------------------------------- directory listing

_LISTING_STRONG = re.compile(r"<(title|h1)>\s*Index of /", re.I)


def directory_listing_outcome(status: int, body: str) -> CheckOutcome:
    if status != 200:
        return CheckOutcome(FindingStatus.NOT_DETECTED,
                            Confidence.HIGH if status in (401, 403, 404) else Confidence.MEDIUM,
                            f"Nessun listing (HTTP {status})", details={"http_status": status})
    if _LISTING_STRONG.search(body):
        return CheckOutcome(FindingStatus.CANDIDATE, Confidence.HIGH,
                            "La cartella uploads mostra l'elenco dei file (firma 'Index of /')",
                            excerpt=_LISTING_STRONG.search(body).group(0),
                            details={"signature": "strong"})
    if "index of" in body.lower():
        markers = has_wp_markers(body)
        return CheckOutcome(
            FindingStatus.CANDIDATE, Confidence.LOW,
            "La pagina contiene la parola 'Index of' ma senza la struttura di un listing"
            + (" ed è una pagina del tema WordPress" if markers else ""),
            details={"signature": "weak", "wp_page_markers": markers,
                     "counter_evidence": "pagina generata da WordPress (soft-404)" if markers else ""})
    return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.HIGH,
                        "HTTP 200 senza elenco di file", details={"http_status": status})


# ---------------------------------------------------------------- debug.log

_PHP_LOG_RE = re.compile(r"PHP (Notice|Warning|Fatal error|Deprecated|Parse error)")


def debug_log_outcome(status: int, body: str) -> CheckOutcome:
    if status == 200 and _PHP_LOG_RE.search(body):
        lines = body.count("\n") + 1
        return CheckOutcome(FindingStatus.CANDIDATE, Confidence.HIGH,
                            f"debug.log pubblico con messaggi PHP (circa {lines} righe; contenuto non conservato)",
                            details={"lines": lines})
    if status == 200:
        return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.MEDIUM,
                            "HTTP 200 ma il contenuto non è un log PHP (probabile pagina del sito)",
                            details={"http_status": status})
    return CheckOutcome(FindingStatus.NOT_DETECTED, Confidence.HIGH,
                        f"debug.log non accessibile (HTTP {status})", details={"http_status": status})


# ---------------------------------------------------------------- login

def login_page_outcome(status: int, body: str) -> CheckOutcome:
    if status == 200 and ('name="log"' in body or "user_login" in body):
        return CheckOutcome(FindingStatus.INFO, Confidence.HIGH,
                            "Pagina di login standard raggiungibile in /wp-login.php (normale in WordPress;"
                            " rilevante solo per il contesto: limitazione dei tentativi, 2FA)")
    return CheckOutcome(FindingStatus.INFO, Confidence.MEDIUM,
                        f"/wp-login.php risponde HTTP {status} (percorso non standard o protetto)")
