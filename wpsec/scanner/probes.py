"""Registro CHIUSO delle richieste HTTP che la piattaforma può inviare.

Gli agenti non costruiscono URL né corpi: chiedono una sonda per nome
(`client.probe("wp.users_rest")`). Metodo, percorso e corpo sono fissi qui,
quindi né un agente né l'IA possono inventare o modificare una richiesta.
Tutte le sonde sono in sola lettura; l'unico POST è system.listMethods di XML-RPC,
che elenca i metodi senza tentare alcun login.
"""

from __future__ import annotations

from dataclasses import dataclass, field

XML_LIST_METHODS = (
    b'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName>'
    b"<params></params></methodCall>"
)


@dataclass(frozen=True)
class Probe:
    id: str
    method: str
    path: str
    description: str
    body: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    scheme: str | None = None          # None = schema del target; "http" per il test di redirect
    cacheable: bool = True

    def __post_init__(self):
        if self.method not in ("GET", "HEAD", "POST"):
            raise ValueError(f"metodo non ammesso: {self.method}")
        if not self.path.startswith("/"):
            raise ValueError("il percorso deve iniziare con /")
        if self.method == "POST" and self.follow_redirects:
            raise ValueError("una POST non deve seguire redirect")


_PROBES = [
    # --- ricognizione
    Probe("home", "GET", "/", "Pagina iniziale (header, meta generator, tecnologie)"),
    Probe("robots", "GET", "/robots.txt", "robots.txt (percorsi dichiarati pubblicamente)"),
    Probe("wp_json_root", "GET", "/wp-json/", "Indice della REST API di WordPress"),
    Probe("http_redirect", "GET", "/", "Versione HTTP del sito (verifica del redirect a HTTPS)",
          scheme="http", follow_redirects=False),
    # --- WordPress
    Probe("wp_users_rest", "GET", "/wp-json/wp/v2/users", "Elenco utenti via REST API"),
    Probe("wp_users_rest_alt", "GET", "/?rest_route=/wp/v2/users",
          "Elenco utenti via REST API (permalink semplici)"),
    Probe("wp_author_1", "GET", "/?author=1", "Archivio del primo autore (enumerazione)"),
    Probe("wp_xmlrpc", "POST", "/xmlrpc.php", "XML-RPC system.listMethods (nessun login)",
          body=XML_LIST_METHODS, headers={"Content-Type": "text/xml"}, follow_redirects=False,
          cacheable=False),
    Probe("wp_uploads", "GET", "/wp-content/uploads/", "Cartella uploads (directory listing)"),
    Probe("wp_feed", "GET", "/feed/", "Feed RSS (tag generator)"),
    Probe("wp_readme", "GET", "/readme.html", "readme.html di WordPress"),
    Probe("wp_login", "GET", "/wp-login.php", "Pagina di login (solo raggiungibilità)",
          follow_redirects=False),
    Probe("wp_debug_log", "GET", "/wp-content/debug.log", "File di log di debug di WordPress"),
]

PROBES: dict[str, Probe] = {p.id: p for p in _PROBES}


def get_probe(probe_id: str) -> Probe:
    try:
        return PROBES[probe_id]
    except KeyError:
        raise KeyError(f"sonda non registrata: {probe_id}") from None
