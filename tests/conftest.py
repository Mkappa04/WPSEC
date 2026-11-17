"""Fixture comuni: siti WordPress simulati e un finto Ollama, su porte casuali.

Nessun test dipende da Internet o da Ollama reale.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import mock_wp  # lab/mock_wp.py (pythonpath in pyproject.toml)

PROFILI_TEST = {
    "wp-vuln": dict(fixes=set()),
    "wp-hard": dict(fixes=set(mock_wp.TUTTE)),
    "wp-mixed": dict(fixes={"xmlrpc", "versione"}),
    "wp-waf": dict(fixes=set(), waf=True),
    "wp-tricky": dict(fixes=set(mock_wp.PROFILI[8085]), tricky=True),
}


def _avvia(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="session")
def mock_sites():
    """{nome: url} di 5 siti simulati (stessi profili di lab/mock_wp.py)."""
    server, urls = [], {}
    for nome, p in PROFILI_TEST.items():
        srv = _avvia(mock_wp.fabbrica(p["fixes"], p.get("waf", False), p.get("tricky", False)))
        server.append(srv)
        urls[nome] = f"http://127.0.0.1:{srv.server_address[1]}"
    yield urls
    for s in server:
        s.shutdown()


class FakeOllama:
    """Finto server Ollama: restituisce risposte programmate e registra i prompt."""

    def __init__(self):
        self.responses = []      # coda di stringhe (campo "response") o eccezioni HTTP (int)
        self.default = '{"spiegazione": "Rischio basso ma da correggere.", "priorita": "media"}'
        self.prompts = []
        self.models = ["qwen3.5:4b", "llama3.2:latest"]
        stato = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                if self.path == "/api/tags":
                    return self._json(200, {"models": [{"name": m} for m in stato.models]})
                self._json(404, {"error": "not found"})

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
                if self.path != "/api/generate":
                    return self._json(404, {"error": "not found"})
                if "prompt" not in body:          # keep_alive=0 (scaricamento modello)
                    return self._json(200, {"done": True, "response": ""})
                stato.prompts.append(body["prompt"])
                r = stato.responses.pop(0) if stato.responses else stato.default
                if isinstance(r, int):
                    return self._json(r, {"error": "token repeat limit reached"})
                self._json(200, {"response": r, "done": True, "done_reason": "stop"})

        self.server = _avvia(H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"


@pytest.fixture
def fake_ollama():
    f = FakeOllama()
    yield f
    f.server.shutdown()


@pytest.fixture
def unused_port():
    """Porta locale su cui nessuno è in ascolto (connessione rifiutata)."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
