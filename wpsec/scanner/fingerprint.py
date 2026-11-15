"""Riconoscimento di tecnologie, WordPress e WAF/CDN (funzioni PURE)."""

from __future__ import annotations

import json
import re

# (nome, header, testo contenuto; "" = basta che l'header esista). Dalla v3, ampliato.
WAF_SIGNATURES = [
    ("BitNinja", "server", "bitninja"),
    ("Cloudflare", "server", "cloudflare"),
    ("Cloudflare", "cf-ray", ""),
    ("Sucuri", "x-sucuri-id", ""),
    ("Sucuri", "server", "sucuri"),
    ("Akamai", "server", "akamai"),
    ("AWS CloudFront", "x-amz-cf-id", ""),
    ("Imperva", "x-iinfo", ""),
    ("Fastly", "x-served-by", ""),
    ("Wordfence", "x-wf-sid", ""),
]

BLOCKING_STATUSES = {403, 429, 503}


def detect_waf(headers: dict[str, str]) -> list[str]:
    found: list[str] = []
    for name, key, needle in WAF_SIGNATURES:
        if key in headers and (not needle or needle in headers[key].lower()) and name not in found:
            found.append(name)
    return found


def looks_like_waf_block(status: int, headers: dict[str, str], body: str, waf: list[str]) -> bool:
    """True se la risposta è plausibilmente un blocco del WAF e non lo stato reale del sito."""
    if status not in BLOCKING_STATUSES:
        return False
    if status in (429, 503):
        return True
    low = (body or "").lower()
    return bool(waf or detect_waf(headers)) or any(
        s in low for s in ("attention required", "access denied", "request blocked", "bitninja",
                           "sucuri website firewall", "wordfence"))


def detect_wordpress(home_status: int, home_headers: dict[str, str], home_body: str,
                     wp_json_status: int, wp_json_body: str) -> tuple[bool, str, list[str]]:
    """Ritorna (rilevato, confidenza, indicatori)."""
    ind: list[str] = []
    body = home_body or ""
    if re.search(r'<meta[^>]+generator[^>]+WordPress', body, re.I):
        ind.append("meta generator WordPress")
    if "/wp-content/" in body or "/wp-includes/" in body:
        ind.append("percorsi /wp-content/ o /wp-includes/ nella home")
    if "https://api.w.org/" in body or "api.w.org" in home_headers.get("link", ""):
        ind.append("link alla REST API (api.w.org)")
    if "x-pingback" in home_headers:
        ind.append("header X-Pingback")
    if wp_json_status == 200:
        try:
            data = json.loads(wp_json_body)
            if isinstance(data, dict) and "wp/v2" in data.get("namespaces", []):
                ind.append("REST API /wp-json/ con namespace wp/v2")
        except (json.JSONDecodeError, TypeError):
            pass
    if len(ind) >= 2:
        return True, "high", ind
    if len(ind) == 1:
        return True, "medium", ind
    return False, "low", ind


def detect_technologies(headers: dict[str, str], body: str) -> dict[str, str]:
    tech = {}
    if headers.get("server"):
        tech["server"] = headers["server"][:80]
    if headers.get("x-powered-by"):
        tech["x-powered-by"] = headers["x-powered-by"][:80]
        m = re.search(r"PHP/([\d.]+)", headers["x-powered-by"])
        if m:
            tech["php"] = m.group(1)
    m = re.search(r"/wp-content/themes/([\w-]+)/", body or "")
    if m:
        tech["wp_theme"] = m.group(1)
    plugins = sorted(set(re.findall(r"/wp-content/plugins/([\w-]+)/", body or "")))
    if plugins:
        tech["wp_plugins_visibili"] = ", ".join(plugins[:15])
    return tech


def robots_paths(status: int, body: str) -> list[str]:
    if status != 200 or "<html" in (body or "").lower():
        return []
    paths = re.findall(r"^\s*(?:Dis)?allow:\s*(\S+)", body or "", re.I | re.M)
    return sorted(set(paths))[:30]
