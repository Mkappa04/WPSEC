"""Avvio di una scansione: controlli preliminari, costruzione di client/contesto/IA,
esecuzione dell'orchestratore e chiusura del risultato.

È l'unico punto d'ingresso usato da CLI, API e test. Prima di qualunque richiesta
verifica che l'autorizzazione sia valida ADESSO e copra il target.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from wpsec import __version__
from wpsec.agents.evidence_agent import EvidenceValidationAgent
from wpsec.agents.http_security_agent import HttpSecurityAgent
from wpsec.agents.reconnaissance_agent import ReconnaissanceAgent
from wpsec.agents.remediation_agent import RemediationAgent
from wpsec.agents.reporting_agent import ReportingAgent
from wpsec.agents.risk_agent import RiskAssessmentAgent
from wpsec.agents.wordpress_agent import WordPressAgent
from wpsec.config.settings import Settings
from wpsec.core.context import ScanContext
from wpsec.core.models import (Authorization, AuthorizationKind, Origin, ScanOptions, ScanResult,
                               now_utc)
from wpsec.core.orchestrator import Orchestrator
from wpsec.knowledge.catalog import CATALOG_VERSION
from wpsec.scanner.http_client import Cancelled, ProxyConfig, ScopedHttpClient

AUTO = "auto"


class ScanRefused(Exception):
    """La scansione non può partire (autorizzazione, perimetro, opzioni)."""


def default_agents():
    return [ReconnaissanceAgent(), WordPressAgent(), HttpSecurityAgent(),
            EvidenceValidationAgent(), RiskAssessmentAgent(), RemediationAgent(),
            ReportingAgent()]


def preflight(target_url: str, auth: Authorization, options: ScanOptions) -> Origin:
    """Controlli che devono passare PRIMA di qualunque richiesta al target."""
    try:
        origin = Origin.from_url(target_url)
    except ValueError as e:
        raise ScanRefused(f"URL del target non valido: {e}") from e
    ok, why = auth.is_valid_at()
    if not ok:
        raise ScanRefused(f"autorizzazione non utilizzabile: {why}")
    if not auth.covers(origin):
        raise ScanRefused(f"{origin.url} non è nel perimetro dell'autorizzazione {auth.id}")
    if auth.kind != AuthorizationKind.LAB:
        if auth.allow_private_addresses:
            raise ScanRefused("indirizzi privati ammessi solo con autorizzazione di laboratorio")
        if auth.allow_active_checks or options.zap_active:
            raise ScanRefused("la scansione attiva è ammessa solo con autorizzazione di laboratorio")
    if options.use_zap:
        raise ScanRefused("integrazione ZAP non ancora disponibile nella v4")
    return origin


def run_scan(target_url: str, authorization: Authorization, options: ScanOptions | None = None,
             settings: Settings | None = None, *, ai=AUTO, resolver=None,
             cancel_event: threading.Event | None = None, agents=None,
             on_update: Callable[[ScanContext], None] | None = None,
             scan_id: str | None = None) -> ScanResult:
    """Esegue una scansione completa e ritorna il risultato (anche se fallita o annullata).

    ai: AUTO = cerca Ollama se options.use_ai; None = nessuna IA; oppure un AIProvider.
    Solleva ScanRefused se i controlli preliminari non passano (nessuna richiesta inviata).
    """
    options = options or ScanOptions()
    settings = settings or Settings.from_env()
    origin = preflight(target_url, authorization, options)
    cancel_event = cancel_event or threading.Event()
    proxy = None
    if options.burp:
        try:
            proxy = ProxyConfig.parse(options.burp)
        except ValueError as e:
            raise ScanRefused(f"proxy non valido: {e}") from e

    client = ScopedHttpClient(authorization, origin, settings, proxy=proxy, resolver=resolver,
                              cancel_event=cancel_event)
    result = ScanResult(platform_version=__version__, catalog_version=CATALOG_VERSION,
                        target=origin.url, host=origin.host, authorization=authorization,
                        options=options, network_mode=client.network_mode,
                        user_agent=settings.effective_user_agent)
    if scan_id:
        result.id = scan_id
    ai_note = ""
    if ai == AUTO:
        ai = None
        if options.use_ai:
            from wpsec.ai.assistant import build_assistant
            ai, ai_note = build_assistant(settings, options.model, cancel_event)
    elif not options.use_ai:
        ai = None
    result.model_used = getattr(ai, "model", "") if ai is not None else ""

    ctx = ScanContext(result, settings, client, ai=ai)
    if ai_note:
        ctx.log("orchestrator", "ai", ai_note)
    t0 = time.monotonic()
    result.status, result.started_at = "running", now_utc()
    try:
        Orchestrator(ctx, agents if agents is not None else default_agents(), on_update).run()
        result.status = "completed"
    except Cancelled:
        result.status, result.error = "cancelled", "scansione annullata dall'utente"
    except Exception as e:  # errore dell'orchestratore stesso, non di un agente
        result.status, result.error = "failed", f"{e.__class__.__name__}: {e}"
        ctx.log("orchestrator", "scan_failed", result.error)
    finally:
        cancel_event.set()  # ferma eventuali agenti scaduti ancora in esecuzione
        with ctx.lock:
            result.finished_at = now_utc()
            result.duration_s = round(time.monotonic() - t0, 2)
            result.stats["http"] = dict(client.stats)
            if ai is not None:
                result.stats["ai"] = dict(getattr(ai, "stats", {}))
        if on_update:
            try:
                on_update(ctx)
            except Exception:
                pass
    return result
