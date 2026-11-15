#!/usr/bin/env python3
"""
Finto server ZAP (API JSON) per provare agente e client SENZA avere ZAP.
Riproduce solo gli endpoint usati da zap_client.py e registra ogni chiamata in `log`,
così i test possono verificare cosa è stato (o non è stato) richiesto, ad esempio
che la scansione attiva non parta mai senza permesso.

NON sostituisce ZAP vero: serve a verificare la logica dell'agente, non la qualità
delle scansioni di ZAP.

Uso manuale:  python3 mock_zap.py   (porta 8090, chiave "chiave-test")
"""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockZap:
    def __init__(self, porta=8090, apikey="chiave-test"):
        self.porta, self.apikey = porta, apikey
        self.log = []                 # lista di (componente, tipo, nome, parametri)
        self.ascan_eseguita = False
        self._spider_chiamate = 0
        self._pscan_chiamate = 0
        self.server = None

    # ---- dati finti -------------------------------------------------------
    def _avvisi(self, baseurl):
        def a(plugin, nome, rischio, codice, path, **extra):
            d = {"pluginId": plugin, "alert": nome, "risk": rischio, "riskcode": codice,
                 "confidence": "Medium", "url": baseurl + path, "param": "", "evidence": "",
                 "cweid": "693", "solution": f"Correzione consigliata per {nome}."}
            d.update(extra)
            return d
        v = [
            a("10038", "Content Security Policy (CSP) Header Not Set", "Medium", "2", "/"),
            a("10021", "X-Content-Type-Options Header Missing", "Low", "1", "/"),
            a("10021", "X-Content-Type-Options Header Missing", "Low", "1", "/wp-login.php"),
            a("10021", "X-Content-Type-Options Header Missing", "Low", "1", "/feed/"),
            a("10109", "Modern Web Application", "Informational", "0", "/"),
        ]
        if self.ascan_eseguita:
            v.append(a("40018", "SQL Injection", "High", "3", "/?s=x", param="s",
                       evidence="You have an error in your SQL syntax", cweid="89"))
        return v

    # ---- server -----------------------------------------------------------
    def avvia(self):
        stato = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, codice, obj):
                corpo = json.dumps(obj).encode()
                self.send_response(codice)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(corpo)))
                self.end_headers()
                self.wfile.write(corpo)

            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                p = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
                parti = u.path.strip("/").split("/")
                if len(parti) != 4 or parti[0] != "JSON":
                    return self._json(404, {"code": "url_not_found", "message": "URL not found"})
                _, comp, tipo, nome = parti
                if stato.apikey and p.get("apikey") != stato.apikey:
                    return self._json(400, {"code": "bad_api_key", "message": "Invalid API Key"})
                stato.log.append((comp, tipo, nome, {k: v for k, v in p.items() if k != "apikey"}))
                chiave = f"{comp}/{tipo}/{nome}"
                if chiave == "core/view/version":
                    return self._json(200, {"version": "2.99.0-mock"})
                if chiave == "spider/action/scan":
                    stato._spider_chiamate = 0
                    return self._json(200, {"scan": "0"})
                if chiave == "spider/view/status":
                    stato._spider_chiamate += 1
                    return self._json(200, {"status": "100" if stato._spider_chiamate > 1 else "40"})
                if chiave == "spider/view/results":
                    return self._json(200, {"results": ["/", "/wp-login.php", "/feed/", "/?p=1"]})
                if chiave == "pscan/view/recordsToScan":
                    stato._pscan_chiamate += 1
                    return self._json(200, {"recordsToScan": "0" if stato._pscan_chiamate > 1 else "3"})
                if chiave == "core/view/alerts":
                    return self._json(200, {"alerts": stato._avvisi(p.get("baseurl", "http://target"))})
                if chiave == "ascan/action/scan":
                    stato.ascan_eseguita = True
                    return self._json(200, {"scan": "1"})
                if chiave == "ascan/view/status":
                    return self._json(200, {"status": "100"})
                # setMode, newContext, includeInContext, accessUrl, setOption..., newSession, stop
                return self._json(200, {"Result": "OK"})

        self.server = ThreadingHTTPServer(("127.0.0.1", self.porta), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def ferma(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


if __name__ == "__main__":
    z = MockZap().avvia()
    print("Finto ZAP su http://127.0.0.1:8090 (chiave: chiave-test). Ctrl+C per fermare.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        z.ferma()
