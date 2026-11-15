"""Client minimale per l'API locale di Ollama (solo libreria standard).

Deriva da analizza_con_ia (v3) e _chiedi_json/riavvia_modello (agente.py):
  - temperatura 0 e seed fisso: a parità di input la risposta è riproducibile;
  - format=json e think=false;
  - risposta vuota con done=false: il runner del modello è bloccato -> lo si scarica
    (keep_alive=0) e si riprova una volta;
  - Ollama è locale: le richieste non passano MAI da proxy (né Burp né di sistema).
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from wpsec.integrations.network import wsl_gateway


class OllamaUnavailable(Exception):
    """Ollama spento o non raggiungibile: inutile riprovare."""


class OllamaError(Exception):
    """Ollama raggiungibile, ma la generazione è fallita."""


class OllamaClient:
    def __init__(self, base_url: str, timeout: float = 90.0, num_gpu: int | None = None,
                 cancel_event: threading.Event | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.num_gpu = num_gpu
        self.cancel_event = cancel_event or threading.Event()
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.restarts = 0

    def _call(self, path: str, body: dict | None, timeout: float) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read().decode()).get("error", "")
            except Exception:
                detail = ""
            raise OllamaError(f"HTTP {e.code}: {detail[:120] or e.reason}") from e
        except urllib.error.URLError as e:
            raise OllamaUnavailable(str(e.reason)) from e
        except (TimeoutError, OSError) as e:
            raise OllamaError(f"timeout o errore di rete: {e}") from e

    def list_models(self) -> list[str]:
        data = self._call("/api/tags", None, 3)
        return [m["name"] for m in data.get("models", []) if "name" in m]

    def unload(self, model: str):
        try:
            self._call("/api/generate", {"model": model, "keep_alive": 0}, 30)
        except (OllamaError, OllamaUnavailable):
            pass
        self.restarts += 1

    def generate(self, prompt: str, model: str, seed: int, max_tokens: int) -> str:
        if self.cancel_event.is_set():
            raise OllamaUnavailable("scansione annullata")
        body = {"model": model, "prompt": prompt, "stream": False, "think": False,
                "format": "json",
                "options": {"num_predict": max_tokens, "temperature": 0, "seed": seed}}
        if self.num_gpu is not None:
            body["options"]["num_gpu"] = self.num_gpu
        for attempt in range(2):
            r = self._call("/api/generate", body, self.timeout)
            text = (r.get("response") or "").strip()
            if text or r.get("done"):
                if r.get("done_reason") == "length" and not text.rstrip().endswith("}"):
                    raise OllamaError("risposta troncata (num_predict insufficiente)")
                return text
            if attempt == 0:
                self.unload(model)
        raise OllamaError("risposta vuota anche dopo il riavvio del modello")


def discover_ollama(preferred: str) -> tuple[str | None, list[str]]:
    """Cerca Ollama sull'URL configurato e, su WSL2, sull'host Windows.
    Ritorna (url, modelli) oppure (None, []). Non modifica nessuno stato globale."""
    candidates = [preferred.rstrip("/")]
    gw = wsl_gateway()
    if gw:
        alt = f"http://{gw}:11434"
        if alt not in candidates:
            candidates.append(alt)
    for url in candidates:
        try:
            return url, OllamaClient(url, timeout=3).list_models()
        except (OllamaError, OllamaUnavailable):
            continue
    return None, []
