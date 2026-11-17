"""Importazione delle scansioni della v3 (scansioni/*.json) nell'archivio v4.

Serve al confronto storico (v3 prima delle correzioni, v4 dopo) e alla valutazione.
Regole:
  - si importano solo host di laboratorio (loopback) o host indicati ESPLICITAMENTE
    dall'operatore come autorizzati; gli host in EXCLUDED_HOSTS sono sempre rifiutati
    (decisione della Fase A: aternos.org non ha un'autorizzazione documentata);
  - la v3 non registrava l'autorizzazione: ne viene creata una segnaposto, marcata come tale;
  - gli esiti della v3 sono riportati così com'erano (source="legacy-v3"): VULNERABILE
    diventa CONFIRMED anche se la v3 non validava le evidenze; il report lo dichiara;
  - gli username nelle evidenze vengono mascherati (minimizzazione).
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from wpsec.core.models import (AINote, Authorization, AuthorizationKind, Confidence, Finding,
                               FindingKind, FindingStatus, Origin, ScanOptions, ScanResult,
                               Severity, StatusChange)
from wpsec.knowledge.catalog import CATALOG
from wpsec.scanner.wordpress_checks import redact_username

EXCLUDED_HOSTS = frozenset({"aternos.org"})

LEGACY_TO_CHECK = {"utenti": "wp.users_rest", "author": "wp.author_enum", "xmlrpc": "wp.xmlrpc",
                   "versione": "wp.version_disclosure", "uploads": "wp.directory_listing",
                   "waf": "recon.waf", "header": "legacy.header"}
STATUS = {"VULNERABILE": FindingStatus.CONFIRMED, "PROTETTO": FindingStatus.NOT_PRESENT,
          "ERRORE": FindingStatus.ERROR, "INFO": FindingStatus.INFO}
SEVERITY = {"critica": Severity.CRITICAL, "alta": Severity.HIGH, "media": Severity.MEDIUM,
            "bassa": Severity.LOW, "info": Severity.INFO, "informativa": Severity.INFO}


class LegacyImportRefused(ValueError):
    pass


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def redact_legacy_text(text: str) -> str:
    text = re.sub(r"slug='([^']*)'", lambda m: f"slug='{redact_username(m.group(1))}'", text or "")
    text = re.sub(r"username '([^']*)'", lambda m: f"username '{redact_username(m.group(1))}'", text)
    return re.sub(r"(/author/)([^/\s]+)", lambda m: m.group(1) + redact_username(m.group(2)), text)


def _finding(r: dict, model: str) -> Finding | None:
    lid = str(r.get("id", ""))
    if lid in ("zap-sintesi", "zap-info"):
        return None   # riepiloghi della v3, non risultati
    status = STATUS.get(str(r.get("esito", "")).upper(), FindingStatus.INCONCLUSIVE)
    if lid.startswith("zap-"):
        check_id, category, kind = f"zap.{lid[4:]}", "zap", FindingKind.MISCONFIGURATION
    else:
        check_id = LEGACY_TO_CHECK.get(lid, f"legacy.{lid}")
        d = CATALOG.get(check_id)
        category = d.category if d else "http"
        kind = d.kind if d else FindingKind.MISCONFIGURATION
    sev = SEVERITY.get(str(r.get("gravita", "")).strip().lower())
    f = Finding(check_id=check_id, legacy_id=lid, title=str(r.get("titolo", lid))[:200],
                category=category, kind=kind, status=status, confidence=Confidence.MEDIUM,
                path=str(r.get("percorso") or "/")[:200],
                summary=redact_legacy_text(str(r.get("evidenza", "")))[:1000], agent="legacy-v3",
                severity=sev if status == FindingStatus.CONFIRMED else None,
                cwe=str(r.get("cwe") or ""),
                rationale="Gravità assegnata dalla v3 (non validata dalla v4)." if sev else "")
    f.history.append(StatusChange(from_status=None, to_status=status, agent="legacy-v3",
                                  reason=f"esito v3: {r.get('esito')}"))
    ia = r.get("ia")
    if isinstance(ia, dict) and ia.get("spiegazione"):
        prio = str(ia.get("priorita", "")).lower()
        f.ai_notes.append(AINote(agent="legacy-v3", model=model or "sconosciuto",
                                 purpose="explanation", text=str(ia["spiegazione"])[:1200],
                                 suggested_priority=prio if prio in ("alta", "media", "bassa") else None,
                                 prompt_version="v3", attempts=int(ia.get("tentativi") or 1)))
    return f


def import_legacy_scan(path: Path | str, authorized_hosts: set[str] = frozenset()) -> ScanResult:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    target = str(data.get("bersaglio", ""))
    origin = Origin.from_url(target)
    if origin.host in EXCLUDED_HOSTS:
        raise LegacyImportRefused(f"{origin.host}: escluso (nessuna autorizzazione documentata)")
    lab = _is_loopback(origin.host)
    if not lab and origin.host not in {h.lower() for h in authorized_hosts}:
        raise LegacyImportRefused(f"{origin.host}: non indicato come autorizzato dall'operatore")
    when = datetime.fromisoformat(data["data"])
    if when.tzinfo is None:
        when = when.astimezone(timezone.utc)
    auth = Authorization(
        id=f"auth-legacy-{origin.host}"[:60],
        kind=AuthorizationKind.LAB if lab else AuthorizationKind.ENGAGEMENT,
        target_url=origin.url, scope=[origin], authorizer_name="Non registrata nella v3",
        authorizer_role="n/d", operator="n/d", valid_from=when, valid_until=when,
        allow_private_addresses=lab,
        notes="Autorizzazione segnaposto creata dall'importazione v3: la v3 non la registrava. "
              "Importata su dichiarazione dell'operatore." if not lab else "Laboratorio locale (v3).")
    model = str(data.get("modello") or "")
    findings = [f for f in (_finding(r, model) for r in data.get("risultati", [])) if f]
    label = re.sub(r"[^\w .:-]", "", str(data.get("etichetta") or ""))[:60]
    stats = {"legacy": {"scanner": data.get("scanner"), "file": Path(path).name}}
    agent = data.get("agente") or {}
    if isinstance(agent, dict) and isinstance(agent.get("stat"), dict):
        stats["legacy"]["agent_stats"] = agent["stat"]
    return ScanResult(platform_version=f"v3-{data.get('scanner', '?')}", catalog_version="v3",
                      target=origin.url, host=origin.host, authorization=auth,
                      options=ScanOptions(model=model, label=label), status="completed",
                      started_at=when, finished_at=when, network_mode=str(data.get("modo_rete", "")),
                      user_agent=str(data.get("user_agent", "")), model_used=model,
                      findings=findings, stats=stats, source="legacy-v3",
                      id=f"scan-v3-{Path(path).stem}"[:80])
