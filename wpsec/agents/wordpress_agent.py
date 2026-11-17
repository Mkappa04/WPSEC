"""WordPress Security Agent: i controlli specifici di WordPress (solo sonde in lettura).

Produce risultati in stato iniziale (CANDIDATE / NOT_DETECTED / ERROR / INFO); non
conferma nulla. Per ogni controllo registra una funzione di ricontrollo che l'Evidence
Validation Agent può usare (richiesta fresca, senza cache).

Correzioni rispetto alla v3:
  - utenti: se il percorso /wp-json/ non dà utenti si prova SEMPRE anche ?rest_route=
    (anche in caso di errore, non solo di 404);
  - versione: meta (qualunque ordine di attributi), feed, readme.html e ?ver= degli asset;
  - blocchi del WAF e risposte 5xx vengono annotati, non letti come "protetto".
"""

from __future__ import annotations

from wpsec.agents.base import BaseAgent, annotate_block, error_outcome, single_probe_check
from wpsec.core.context import ScanContext
from wpsec.core.models import FindingStatus
from wpsec.scanner import wordpress_checks as wc


class WordPressAgent(BaseAgent):
    name = "wordpress"
    display_name = "WordPress Security Agent"
    description = ("Utenti REST, enumerazione autori, XML-RPC, versione, directory listing, "
                   "debug.log, pagina di login")
    depends_on = ("recon",)
    requires = ("recon",)

    def should_run(self, ctx: ScanContext) -> tuple[bool, str]:
        wp = ctx.shared.get("wordpress", {})
        if wp.get("detected"):
            return True, ""
        if ctx.result.options.force_wordpress:
            return True, "WordPress non rilevato, controlli forzati dall'operatore"
        return False, "WordPress non rilevato dalla Reconnaissance (usare force_wordpress per forzare)"

    def run(self, ctx: ScanContext) -> str:
        redact = ctx.settings.redact_usernames
        self._users(ctx, redact)
        single_probe_check(ctx, self.name, "wp.author_enum", "wp_author_1",
                           lambda r: wc.author_outcome(
                               r.status, r.body,
                               r.redirect_chain + [r.final_url, r.redirect_blocked], redact),
                           "/?author=1")
        single_probe_check(ctx, self.name, "wp.xmlrpc", "wp_xmlrpc",
                           lambda r: wc.xmlrpc_outcome(r.status, r.body), "/xmlrpc.php")
        self._version(ctx)
        single_probe_check(ctx, self.name, "wp.directory_listing", "wp_uploads",
                           lambda r: wc.directory_listing_outcome(r.status, r.body),
                           "/wp-content/uploads/")
        single_probe_check(ctx, self.name, "wp.debug_log", "wp_debug_log",
                           lambda r: wc.debug_log_outcome(r.status, r.body),
                           "/wp-content/debug.log")
        single_probe_check(ctx, self.name, "wp.login_page", "wp_login",
                           lambda r: wc.login_page_outcome(r.status, r.body), "/wp-login.php")
        candidates = [f.check_id for f in ctx.findings
                      if f.agent == self.name and f.status == FindingStatus.CANDIDATE]
        return f"{len(candidates)} candidati: {', '.join(candidates) or 'nessuno'}"

    # ------------------------------------------------------------ utenti
    def _users(self, ctx: ScanContext, redact: bool):
        def execute(fresh: bool = False):
            ids, blocked, last = [], False, None
            for probe_id, path in (("wp_users_rest", "/wp-json/wp/v2/users"),
                                   ("wp_users_rest_alt", "/?rest_route=/wp/v2/users")):
                r = ctx.client.probe(probe_id, fresh=fresh)
                ids.append(r.evidence.id)
                o = error_outcome(r) if not r.ok else wc.users_outcome(r.status, r.body, path, redact)
                annotate_block(ctx, o, r)
                blocked = blocked or bool(o.details.get("waf_block"))
                if o.status == FindingStatus.CANDIDATE:
                    return o, ids
                # a parità di esito negativo si tiene il più informativo (non l'errore)
                if last is None or last.status == FindingStatus.ERROR:
                    last = o
            if blocked:
                last.details["waf_block"] = True
            last.details["paths_checked"] = 2
            return last, ids

        outcome, ids = execute()
        ctx.add_finding("wp.users_rest", outcome, self.name, ids, path="/wp-json/wp/v2/users",
                        recheck=lambda: execute(True))

    # ------------------------------------------------------------ versione
    def _version(self, ctx: ScanContext):
        def execute(fresh: bool = False):
            home = ctx.client.probe("home", fresh=fresh) if fresh else ctx.shared.get("home")
            if home is None:
                home = ctx.client.probe("home")
            feed = ctx.client.probe("wp_feed", fresh=fresh)
            readme = ctx.client.probe("wp_readme", fresh=fresh)
            sources = {
                "meta": wc.version_from_meta(home.body) if home.ok else None,
                "feed": wc.version_from_feed(feed.body) if feed.ok and feed.status == 200 else None,
                "readme": (wc.version_from_readme(readme.body)
                           if readme.ok and readme.status == 200 else None),
                "assets": wc.version_from_assets(home.body) if home.ok else None,
            }
            o = wc.version_outcome(sources)
            responses = {"meta": home, "assets": home, "feed": feed, "readme": readme}
            if o.status == FindingStatus.CANDIDATE:
                ids = list(dict.fromkeys(responses[k].evidence.id for k in o.details["sources"]))
            else:
                ids = [home.evidence.id, feed.evidence.id, readme.evidence.id]
                errors = [r for r in (home, feed, readme) if not r.ok]
                if len(errors) == 3:
                    o = error_outcome(errors[0])
                elif errors:
                    o.details["partial_errors"] = [r.probe_id for r in errors]
                for r in (feed, readme):
                    annotate_block(ctx, o, r)
            return o, ids

        outcome, ids = execute()
        ctx.add_finding("wp.version_disclosure", outcome, self.name, ids, path="/",
                        recheck=lambda: execute(True))
