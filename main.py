#!/usr/bin/env python3
"""wpsec: riga di comando della piattaforma v4.

Esempi:
  python main.py auth add --kind lab --target http://127.0.0.1:8081 --by Tutor --role Tutor --operator Studente
  python main.py scan --lab http://127.0.0.1:8081 --label prima --no-ai
  python main.py auth add --target https://www.sito.it --by "Mario Rossi" --role Titolare \\
        --operator Studente --doc "Lettera del 10/11/2026" --doc-file lettera.pdf --days 7
  python main.py scan --auth auth-xxxx --target https://www.sito.it --label dopo
  python main.py list
  python main.py report scan-xxxx --formats html,pdf --anonymize
  python main.py compare --host 127.0.0.1
  python main.py import-v3 scansioni/127.0.0.1_8081_*.json
  python main.py serve
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from wpsec import __version__
from wpsec.config.settings import Settings

EXIT_REFUSED = 2


def _settings(args) -> Settings:
    s = Settings.from_env()
    if args.data_dir:
        s = s.with_overrides(data_dir=Path(args.data_dir))
    return s


def _store(settings):
    from wpsec.database.store import Store
    return Store(settings.db_path)


# ------------------------------------------------------------ autorizzazioni
def cmd_auth_add(args, settings):
    from wpsec.core.authorization import AuthorizationRequest, create_authorization, sha256_file
    sha = sha256_file(args.doc_file) if args.doc_file else ""
    req = AuthorizationRequest(kind=args.kind, target_url=args.target, extra_scope=args.scope or [],
                               authorizer_name=args.by, authorizer_role=args.role,
                               operator=args.operator, document_ref=args.doc or "",
                               document_sha256=sha, days=args.days,
                               allow_active_checks=args.allow_active, notes=args.notes or "")
    auth = _store(settings).save_authorization(create_authorization(req))
    print(f"Autorizzazione registrata: {auth.id}")
    print(f"  perimetro: {', '.join(o.url for o in auth.scope)}")
    print(f"  valida dal {auth.valid_from:%Y-%m-%d %H:%M} al {auth.valid_until:%Y-%m-%d %H:%M} UTC")
    if sha:
        print(f"  documento: {args.doc_file} (sha256 {sha[:16]}…)")


def cmd_auth_list(args, settings):
    auths = _store(settings).list_authorizations(only_valid=args.valid)
    if not auths:
        print("Nessuna autorizzazione.")
    for a in auths:
        ok, why = a.is_valid_at()
        print(f"{a.id}  {a.kind.value:10}  {a.target_url:40}  {why:30}  {a.authorizer_name}")


def cmd_auth_revoke(args, settings):
    a = _store(settings).revoke_authorization(args.id)
    print(f"Autorizzazione {a.id} revocata.")


# ------------------------------------------------------------ scansione
def _lab_authorization(store, url):
    from wpsec.core.authorization import AuthorizationRequest, create_authorization
    from wpsec.core.models import Origin
    wanted = Origin.from_url(url)
    for a in store.list_authorizations(only_valid=True):
        if a.kind.value == "lab" and a.covers(wanted):
            return a
    return store.save_authorization(create_authorization(AuthorizationRequest(
        kind="lab", target_url=url, authorizer_name="Laboratorio locale", authorizer_role="Tutor",
        operator="Operatore", days=30, notes="Creata automaticamente da 'scan --lab'.")))


def cmd_scan(args, settings):
    from wpsec.core.models import AgentState, ScanOptions
    from wpsec.core.scan import run_scan
    from wpsec.reports import write_reports
    store = _store(settings)
    if args.lab:
        auth, target = _lab_authorization(store, args.lab), args.lab
    else:
        if not (args.auth and args.target):
            sys.exit("Indicare --auth e --target, oppure --lab URL per il laboratorio locale.")
        auth, target = store.get_authorization(args.auth), args.target
    options = ScanOptions(label=args.label or "", model=args.model or "", use_ai=not args.no_ai,
                          planner=args.planner, burp=args.burp or "",
                          force_wordpress=args.force_wordpress)
    seen: dict[str, str] = {}

    def progress(ctx):
        for a in ctx.result.agents:
            if seen.get(a.name) != a.state.value and a.state != AgentState.PENDING:
                seen[a.name] = a.state.value
                if a.state == AgentState.RUNNING:
                    print(f"  … {a.display_name}", flush=True)
                else:
                    print(f"  [{a.state.value}] {a.display_name}: {a.message or a.error or ''}",
                          flush=True)

    print(f"Scansione di {target} (autorizzazione {auth.id})")
    result = run_scan(target, auth, options, settings, on_update=progress)
    store.save_scan(result)
    print(f"\nStato: {result.status} in {result.duration_s}s, "
          f"{result.stats.get('http', {}).get('requests', 0)} richieste. ID: {result.id}")
    print(result.executive_summary)
    formats = [f for f in args.formats.split(",") if f]
    if formats:
        paths = write_reports(result, settings.reports_dir, formats, anonymize=args.anonymize)
        for fmt, p in paths.items():
            print(f"  report {fmt}: {p}")
    return 0 if result.status == "completed" else 1


def cmd_list(args, settings):
    rows = _store(settings).list_scans(host=args.host, limit=args.limit)
    if not rows:
        print("Nessuna scansione.")
    for r in rows:
        sev = " ".join(f"{k[0].upper()}{v}" for k, v in r["severity"].items() if v) or "-"
        print(f"{r['id']:24} {r['started_at'][:16]}  {r['status']:9} {r['source']:9} "
              f"{r['target']:35} conf={r['confirmed']:<3} inc={r['inconclusive']:<3} {sev} "
              f"{r['label']}")


def cmd_report(args, settings):
    from wpsec.reports import write_reports
    result = _store(settings).get_scan(args.scan_id)
    out = Path(args.out) if args.out else settings.reports_dir
    for fmt, p in write_reports(result, out, args.formats.split(","), args.anonymize).items():
        print(f"{fmt}: {p}")


def cmd_compare(args, settings):
    from wpsec.comparison.compare import compare, to_markdown
    store = _store(settings)
    if args.before and args.after:
        b, a = store.get_scan(args.before), store.get_scan(args.after)
    elif args.host:
        b, a = store.latest_pair(args.host)
    else:
        sys.exit("Indicare due ID di scansione oppure --host.")
    text = to_markdown(compare(b, a), anonymize=args.anonymize)
    print(text)
    if args.save:
        settings.reports_dir.mkdir(parents=True, exist_ok=True)
        p = settings.reports_dir / f"confronto_{b.id}_{a.id}.md"
        p.write_text(text, encoding="utf-8")
        print(f"Salvato in {p}")


def cmd_import(args, settings):
    from wpsec.database.legacy import LegacyImportRefused, import_legacy_scan
    store = _store(settings)
    hosts = set(args.authorized_host or [])
    code = 0
    for f in args.files:
        try:
            r = import_legacy_scan(f, hosts)
            store.save_scan(r)
            print(f"importato  {f} -> {r.id} ({len(r.findings)} risultati)")
        except LegacyImportRefused as e:
            print(f"rifiutato  {f}: {e}")
            code = EXIT_REFUSED
    return code


def cmd_models(args, settings):
    from wpsec.ai.ollama_client import discover_ollama
    url, models = discover_ollama(settings.ollama_url)
    if not url:
        print("Ollama non raggiungibile.")
        return 1
    print(f"Ollama su {url}")
    for m in models:
        print(f"  {'*' if m == settings.default_model else ' '} {m}")


def cmd_serve(args, settings):
    import uvicorn
    from wpsec.core.authorization import is_loopback_host
    from wpsec.web.app import create_app
    host = args.host or settings.web_host
    if not is_loopback_host(host) and not args.allow_remote:
        sys.exit(f"L'interfaccia non ha autenticazione: ascolta solo in locale. Per {host} "
                 "usare --allow-remote (sconsigliato).")
    settings = settings.with_overrides(web_host=host, web_port=args.port or settings.web_port)
    app = create_app(settings, extra_hosts=[host] if args.allow_remote else [])
    print(f"Dashboard: http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{settings.web_port}/")
    uvicorn.run(app, host=host, port=settings.web_port, log_level="warning")


# ------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wpsec", description="Vulnerability assessment WordPress "
                                "non invasivo, multi-agente, con IA locale.")
    p.add_argument("--version", action="version", version=f"wpsec {__version__}")
    p.add_argument("--data-dir", help="cartella di database e report (predefinita: ./data)")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("auth", help="gestione delle autorizzazioni")
    asub = a.add_subparsers(dest="auth_cmd", required=True)
    add = asub.add_parser("add", help="registra un'autorizzazione")
    add.add_argument("--kind", choices=["engagement", "lab"], default="engagement")
    add.add_argument("--target", required=True)
    add.add_argument("--scope", nargs="*", help="altre origini nel perimetro")
    add.add_argument("--by", required=True, help="chi autorizza")
    add.add_argument("--role", required=True, help="ruolo di chi autorizza")
    add.add_argument("--operator", required=True)
    add.add_argument("--doc", help="riferimento al documento firmato (obbligatorio per i siti reali)")
    add.add_argument("--doc-file", help="file del documento: ne viene registrato lo SHA-256")
    add.add_argument("--days", type=int)
    add.add_argument("--allow-active", action="store_true", help="scansione attiva (solo lab)")
    add.add_argument("--notes")
    add.set_defaults(func=cmd_auth_add)
    ls = asub.add_parser("list")
    ls.add_argument("--valid", action="store_true", help="solo quelle valide adesso")
    ls.set_defaults(func=cmd_auth_list)
    rv = asub.add_parser("revoke")
    rv.add_argument("id")
    rv.set_defaults(func=cmd_auth_revoke)

    s = sub.add_parser("scan", help="esegue una scansione")
    s.add_argument("--auth", help="ID dell'autorizzazione")
    s.add_argument("--target")
    s.add_argument("--lab", metavar="URL", help="laboratorio locale: crea/riusa un'autorizzazione lab")
    s.add_argument("--label")
    s.add_argument("--model")
    s.add_argument("--no-ai", action="store_true")
    s.add_argument("--planner", choices=["deterministic", "llm"], default="deterministic")
    s.add_argument("--burp", help="proxy Burp host:porta")
    s.add_argument("--force-wordpress", action="store_true")
    s.add_argument("--formats", default="html,md,json", help="report da scrivere (vuoto = nessuno)")
    s.add_argument("--anonymize", action="store_true")
    s.set_defaults(func=cmd_scan)

    li = sub.add_parser("list", help="elenca le scansioni")
    li.add_argument("--host")
    li.add_argument("--limit", type=int, default=30)
    li.set_defaults(func=cmd_list)

    r = sub.add_parser("report", help="genera i report di una scansione archiviata")
    r.add_argument("scan_id")
    r.add_argument("--formats", default="html,pdf,md,json")
    r.add_argument("--anonymize", action="store_true")
    r.add_argument("--out")
    r.set_defaults(func=cmd_report)

    c = sub.add_parser("compare", help="confronto prima/dopo")
    c.add_argument("before", nargs="?")
    c.add_argument("after", nargs="?")
    c.add_argument("--host", help="ultime due scansioni completate dell'host")
    c.add_argument("--anonymize", action="store_true")
    c.add_argument("--save", action="store_true")
    c.set_defaults(func=cmd_compare)

    im = sub.add_parser("import-v3", help="importa scansioni JSON della v3")
    im.add_argument("files", nargs="+")
    im.add_argument("--authorized-host", action="append",
                    help="host reale autorizzato (ripetibile); il laboratorio è sempre ammesso")
    im.set_defaults(func=cmd_import)

    m = sub.add_parser("models", help="modelli disponibili in Ollama")
    m.set_defaults(func=cmd_models)

    sv = sub.add_parser("serve", help="avvia API e dashboard")
    sv.add_argument("--host")
    sv.add_argument("--port", type=int)
    sv.add_argument("--allow-remote", action="store_true")
    sv.set_defaults(func=cmd_serve)
    return p


def main(argv=None) -> int:
    from pydantic import ValidationError
    from wpsec.comparison.compare import ComparisonError
    from wpsec.core.authorization import AuthorizationError
    from wpsec.core.scan import ScanRefused
    from wpsec.database.store import NotFound
    args = build_parser().parse_args(argv)
    settings = _settings(args)
    try:
        return args.func(args, settings) or 0
    except (ScanRefused, AuthorizationError, ComparisonError, NotFound, ValidationError, ValueError) as e:
        msg = str(e).strip("'\"")
        if isinstance(e, ValidationError):
            msg = "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())
        print(f"Errore: {msg}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
