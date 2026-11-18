#!/usr/bin/env python3
"""
Simulatore leggero di 3 siti WordPress, per provare il benchmark SENZA Docker.
Riproduce solo i comportamenti guardati dai 6 controlli, quindi NON sostituisce
il laboratorio vero (non può rivelare falsi positivi dovuti a WordPress reale).

Avvio:  python3 mock_wp.py     (porte 8081, 8082, 8083 su 127.0.0.1)
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TUTTE = {"utenti", "author", "xmlrpc", "header", "versione", "uploads"}
PROFILI = {
    8081: set(),                      # wp-vuln: nessuna correzione
    8082: set(TUTTE),                 # wp-hard: tutte
    8083: {"xmlrpc", "versione"},     # wp-mixed
    8084: set(),                      # solo per provare il rilevamento WAF (non è nella ground truth)
}
PORTE_CON_WAF = {8084}
# wp-tricky: casi difficili per lo scanner v3 (blocco WAF scambiato per protezione,
# falso directory listing, versione esposta solo nel feed). Serve a misurare
# l'Evidence Validation Agent della piattaforma v4.
PORTE_TRICKY = {8085}
PROFILI[8085] = {"author", "xmlrpc", "header", "versione"}

HEADER_SICUREZZA = {
    "Strict-Transport-Security": "max-age=300",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}

METODI = (b'<?xml version="1.0"?><methodResponse><params><param><value><array><data>'
          b'<value><string>system.multicall</string></value>'
          b'<value><string>wp.getUsersBlogs</string></value>'
          b'</data></array></value></param></params></methodResponse>')


PAGINA_TRICKY = (
    '<html><head><link rel="https://api.w.org/" href="/wp-json/"></head>'
    '<body class="home blog"><article><h2>Guida: cos\'è la pagina "Index of /"?</h2>'
    "<p>Quando un server mostra Index of /cartella significa che...</p></article>"
    '<script src="/wp-content/themes/twentytwentyfour/app.js"></script></body></html>'
)


def fabbrica(fixes, waf=False, tricky=False):
    class H(BaseHTTPRequestHandler):
        if waf or tricky:
            server_version = "cloudflare" if tricky else "BitNinja-WafPro"
            sys_version = ""

        def log_message(self, *a):
            pass

        def _r(self, codice, corpo=b"", tipo="text/html", extra=None):
            if isinstance(corpo, str):
                corpo = corpo.encode()
            self.send_response(codice)
            self.send_header("Content-Type", tipo)
            self.send_header("Content-Length", str(len(corpo)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(corpo)

        def do_GET(self):
            p = self.path
            if tricky:
                if "users" in p:
                    # il WAF blocca la richiesta: non si sa se gli utenti siano esposti
                    return self._r(403, "<html>Attention Required! | Cloudflare</html>",
                                   extra={"CF-RAY": "8a1b2c3d4e5f-MXP"})
                if p.startswith("/wp-content/uploads"):
                    # soft-404: pagina del tema che contiene la scritta "Index of"
                    return self._r(200, PAGINA_TRICKY)
                if p.startswith("/feed"):
                    return self._r(200, "<?xml version=\"1.0\"?><rss><channel>"
                                   "<generator>https://wordpress.org/?v=6.8.1</generator>"
                                   "</channel></rss>", "application/rss+xml")
            if p.startswith("/feed") or p.startswith("/?feed="):
                gen = "" if "versione" in fixes else "<generator>https://wordpress.org/?v=6.8.1</generator>"
                return self._r(200, f"<?xml version=\"1.0\"?><rss><channel>{gen}</channel></rss>",
                               "application/rss+xml")
            if p.startswith("/wp-json/wp/v2/users") or p.startswith("/?rest_route=/wp/v2/users"):
                if "utenti" in fixes:
                    return self._r(401, '{"code":"rest_cannot_access"}', "application/json")
                return self._r(200, '[{"id":1,"name":"admin","slug":"admin"}]', "application/json")
            if p.startswith("/?author="):
                dest = "/" if "author" in fixes else "/author/admin/"
                return self._r(301, b"", extra={"Location": dest})
            if p.startswith("/author/"):
                return self._r(200, "<html>archivio autore</html>")
            if p.startswith("/wp-content/uploads"):
                if "uploads" in fixes:
                    return self._r(403, "Forbidden")
                return self._r(200, "<html><h1>Index of /wp-content/uploads</h1></html>")
            if p.startswith("/xmlrpc.php"):
                return self._r(405 if "xmlrpc" not in fixes else 403, "XML-RPC server accepts POST requests only.")
            if p == "/":
                gen = "" if "versione" in fixes else '<meta name="generator" content="WordPress 6.8.1" />'
                extra = HEADER_SICUREZZA if "header" in fixes else {}
                if tricky:
                    extra = dict(extra, **{"Content-Security-Policy":
                                           "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'",
                                           "CF-RAY": "8a1b2c3d4e5f-MXP"})
                return self._r(200, f'<html><head>{gen}<link rel="https://api.w.org/" href="/wp-json/">'
                               f'</head><body class="home">home</body></html>', extra=extra)
            self._r(404, "non trovato")

        def do_POST(self):
            if self.path.startswith("/xmlrpc.php"):
                n = int(self.headers.get("Content-Length", 0))
                self.rfile.read(n)
                if tricky:
                    # endpoint raggiungibile ma metodi disabilitati: risponde con <fault>
                    return self._r(200, b'<?xml version="1.0"?><methodResponse><fault><value><struct>'
                                   b'<member><name>faultCode</name><value><int>405</int></value></member>'
                                   b'</struct></value></fault></methodResponse>', "text/xml")
                if "xmlrpc" in fixes:
                    return self._r(403, "Forbidden")
                return self._r(200, METODI, "text/xml")
            self._r(404, "non trovato")

    return H


if __name__ == "__main__":
    server = []
    for porta, fixes in PROFILI.items():
        s = ThreadingHTTPServer(("127.0.0.1", porta),
                                fabbrica(fixes, porta in PORTE_CON_WAF, porta in PORTE_TRICKY))
        threading.Thread(target=s.serve_forever, daemon=True).start()
        server.append(s)
        print(f"Simulatore su http://127.0.0.1:{porta}  (correzioni: {sorted(fixes) or 'nessuna'})")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nChiuso.")
