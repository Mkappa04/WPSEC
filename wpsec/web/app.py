"""API FastAPI e dashboard locale.

Sicurezza dell'interfaccia (pensata per girare su 127.0.0.1):
  - Host ammessi solo locali (TrustedHostMiddleware): blocca il DNS rebinding;
  - richieste che modificano lo stato: Origin, se presente, deve essere locale, e il corpo
    deve essere JSON (un form HTML di un altro sito non può inviarlo senza preflight CORS);
    nessun CORS abilitato;
  - CSP restrittiva: solo script e stili serviti dall'app stessa, niente inline;
  - i report HTML vengono serviti con CSP "sandbox" (nessuno script, origine isolata).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from wpsec import __version__
from wpsec.comparison.compare import ComparisonError, compare, to_markdown
from wpsec.config.settings import Settings
from wpsec.core.authorization import AuthorizationError, AuthorizationRequest, create_authorization
from wpsec.core.models import ScanOptions
from wpsec.core.scan import AUTO, ScanRefused
from wpsec.database.store import NotFound, Store
from wpsec.knowledge.catalog import CATALOG, CATALOG_VERSION
from wpsec.reports import FORMATS, render
from wpsec.web.scan_manager import Busy, ScanManager

STATIC = Path(__file__).parent / "static"
LOCAL_HOSTS = ["127.0.0.1", "localhost", "::1", "[::1]", "testserver"]
MEDIA = {"json": "application/json", "md": "text/markdown; charset=utf-8",
         "html": "text/html; charset=utf-8", "pdf": "application/pdf"}
APP_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"


class ScanStart(BaseModel):
    authorization_id: str = Field(min_length=3, max_length=80)
    target_url: str = Field(min_length=8, max_length=300)
    options: ScanOptions = Field(default_factory=ScanOptions)


def create_app(settings: Settings | None = None, store: Store | None = None, ai=AUTO,
               resolver=None, extra_hosts: list[str] = ()) -> FastAPI:
    settings = settings or Settings.from_env()
    store = store or Store(settings.db_path)
    manager = ScanManager(store, settings, ai=ai, resolver=resolver)
    hosts = list(dict.fromkeys([*LOCAL_HOSTS, settings.web_host, *extra_hosts]))

    @asynccontextmanager
    async def lifespan(app):
        n = store.mark_interrupted()
        app.state.interrupted_at_startup = n
        yield
        manager.shutdown()

    app = FastAPI(title="wpsec", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.state.store, app.state.manager, app.state.settings = store, manager, settings
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and (urlsplit(origin).hostname or "") not in hosts:
                return JSONResponse({"detail": "origine non ammessa"}, status_code=403)
            ctype = request.headers.get("content-type", "")
            has_body = request.headers.get("content-length", "0") not in ("", "0")
            if has_body and not ctype.startswith("application/json"):
                return JSONResponse({"detail": "il corpo deve essere JSON"}, status_code=415)
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", APP_CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    # ------------------------------------------------------------ errori
    def _err(status: int):
        async def handler(request, exc):
            return JSONResponse({"detail": str(exc).strip("'\"")}, status_code=status)
        return handler

    app.add_exception_handler(NotFound, _err(404))
    for exc in (ScanRefused, AuthorizationError, ComparisonError):
        app.add_exception_handler(exc, _err(400))
    app.add_exception_handler(Busy, _err(429))

    # ------------------------------------------------------------ dashboard
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html", media_type="text/html")

    # ------------------------------------------------------------ informazioni
    @app.get("/api/health")
    def health():
        return {"version": __version__, "catalog_version": CATALOG_VERSION,
                "running": len(manager.running()),
                "max_concurrent_scans": settings.max_concurrent_scans}

    @app.get("/api/models")
    def models():
        from wpsec.ai.ollama_client import discover_ollama
        url, names = discover_ollama(settings.ollama_url)
        return {"available": bool(url), "url": url, "models": names,
                "default": settings.default_model}

    @app.get("/api/catalog")
    def catalog():
        return [{"check_id": d.check_id, "title": d.title, "category": d.category,
                 "kind": d.kind.value, "severity": d.severity.value, "cwe": d.cwe,
                 "rationale": d.rationale} for d in CATALOG.values()]

    # ------------------------------------------------------------ autorizzazioni
    @app.get("/api/authorizations")
    def list_authorizations(only_valid: bool = False):
        return [a.model_dump(mode="json") for a in store.list_authorizations(only_valid)]

    @app.post("/api/authorizations", status_code=201)
    def add_authorization(req: AuthorizationRequest):
        return store.save_authorization(create_authorization(req)).model_dump(mode="json")

    @app.get("/api/authorizations/{auth_id}")
    def get_authorization(auth_id: str):
        return store.get_authorization(auth_id).model_dump(mode="json")

    @app.post("/api/authorizations/{auth_id}/revoke")
    def revoke_authorization(auth_id: str):
        return store.revoke_authorization(auth_id).model_dump(mode="json")

    # ------------------------------------------------------------ scansioni
    @app.post("/api/scans", status_code=202)
    def start_scan(req: ScanStart):
        scan_id = manager.start(req.authorization_id, req.target_url, req.options)
        return {"id": scan_id, "status": "running"}

    @app.get("/api/scans")
    def list_scans(host: str | None = None, limit: int = Query(50, ge=1, le=500)):
        rows = store.list_scans(host=host, limit=limit)
        running = {r["id"] for r in manager.running()}
        for r in rows:
            r["live"] = r["id"] in running
        return rows

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str, trace: bool = False):
        r = manager.get(scan_id)
        data = r.model_dump(mode="json", exclude=None if trace else {"trace"})
        data["live"] = manager.is_running(scan_id)
        return data

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str):
        if not manager.cancel(scan_id):
            raise HTTPException(409, "la scansione non è in corso")
        return {"id": scan_id, "cancel_requested": True}

    @app.delete("/api/scans/{scan_id}", status_code=204)
    def delete_scan(scan_id: str):
        if manager.is_running(scan_id):
            raise HTTPException(409, "annullare la scansione prima di cancellarla")
        store.delete_scan(scan_id)
        return Response(status_code=204)

    @app.get("/api/scans/{scan_id}/report.{fmt}")
    def report(scan_id: str, fmt: str, anonymize: bool = False):
        if fmt not in FORMATS:
            raise HTTPException(404, f"formato non supportato: {fmt}")
        if manager.is_running(scan_id):
            raise HTTPException(409, "report disponibile a scansione conclusa")
        try:
            body = render(store.get_scan(scan_id), fmt, anonymize)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        name = f"{scan_id}{'-anon' if anonymize else ''}.{fmt}"
        disposition = "inline" if fmt == "html" else "attachment"
        return Response(body, media_type=MEDIA[fmt], headers={
            "Content-Disposition": f'{disposition}; filename="{name}"',
            "Content-Security-Policy": REPORT_CSP})

    # ------------------------------------------------------------ confronto
    @app.get("/api/compare")
    def compare_scans(before: str | None = None, after: str | None = None,
                      host: str | None = None, format: str = "json", anonymize: bool = False):
        if before and after:
            b, a = store.get_scan(before), store.get_scan(after)
        elif host:
            b, a = store.latest_pair(host)
        else:
            raise HTTPException(400, "indicare before e after oppure host")
        c = compare(b, a)
        if format == "md":
            return Response(to_markdown(c, anonymize), media_type=MEDIA["md"])
        data = c.model_dump(mode="json")
        data["counts"] = c.counts()
        return data

    @app.get("/api/history")
    def history(host: str, check_id: str):
        return store.finding_history(host, check_id)

    @app.get("/api/timeline")
    def timeline(host: str):
        """Andamento di ogni problema dell'host nelle scansioni completate."""
        return store.issue_timeline(host)

    @app.get("/api/findings/{finding_id}/evidence")
    def finding_evidence(finding_id: str):
        return {"evidence": store.evidence_for_finding(finding_id),
                "status_history": store.status_history(finding_id)}

    return app
