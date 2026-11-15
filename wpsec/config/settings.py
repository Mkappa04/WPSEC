"""Configurazione della piattaforma.

Sostituisce le variabili globali modificabili della v3 (USER_AGENT, PAUSA_TRA_RICHIESTE,
URL_OLLAMA...): le impostazioni sono un oggetto IMMUTABILE passato esplicitamente a chi
ne ha bisogno, quindi due scansioni contemporanee non possono influenzarsi a vicenda.
I valori si possono sovrascrivere con variabili d'ambiente WPSEC_*.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from wpsec import __version__

ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default, cast=str):
    raw = os.environ.get(f"WPSEC_{name}")
    if raw is None or raw == "":
        return default
    try:
        return cast(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # --- rete verso il target
    request_timeout: float = 20.0
    min_interval: float = 0.5          # pausa minima tra due richieste allo stesso target (s)
    max_requests: int = 150            # budget massimo di richieste per scansione
    max_redirects: int = 5
    max_body_bytes: int = 500_000
    user_agent: str = ""               # vuoto = User-Agent dichiarato (consigliato)
    contact: str = ""                  # contatto mostrato nello User-Agent dichiarato

    # --- IA locale (Ollama)
    ollama_url: str = "http://127.0.0.1:11434"
    default_model: str = "qwen3.5:4b"
    ai_timeout: float = 90.0
    ai_max_tokens: int = 600
    ai_seed: int = 42
    ai_retries: int = 2
    ai_max_explanations: int = 12      # massimo di risultati spiegati dall'IA per scansione
    ai_num_gpu: int | None = None      # 0 = solo CPU (utile se la GPU dà errori CUDA)

    # --- orchestratore
    agent_timeout: float = 300.0       # timeout di ciascun agente (s)
    planner_max_steps: int = 12
    planner_max_invalid: int = 3

    # --- dati
    data_dir: Path = field(default_factory=lambda: ROOT / "data")
    redact_usernames: bool = True      # minimizzazione: username mascherati nelle evidenze

    # --- interfaccia web
    web_host: str = "127.0.0.1"
    web_port: int = 8000
    max_concurrent_scans: int = 1

    @property
    def db_path(self) -> Path:
        return self.data_dir / "wpsec.sqlite3"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def effective_user_agent(self) -> str:
        if self.user_agent:
            return self.user_agent
        base = f"TirocinioPentest/{__version__} (scanner didattico non invasivo"
        return base + (f"; contatto: {self.contact})" if self.contact else ")")

    def with_overrides(self, **kw) -> "Settings":
        return replace(self, **{k: v for k, v in kw.items() if v is not None})

    @classmethod
    def from_env(cls) -> "Settings":
        d = cls()
        gpu = _env("AI_NUM_GPU", None, int)
        legacy_gpu = os.environ.get("PENTEST_NUM_GPU", "").strip()
        if gpu is None and legacy_gpu.isdigit():  # compatibilità con la variabile della v3
            gpu = int(legacy_gpu)
        return cls(
            request_timeout=_env("REQUEST_TIMEOUT", d.request_timeout, float),
            min_interval=_env("MIN_INTERVAL", d.min_interval, float),
            max_requests=_env("MAX_REQUESTS", d.max_requests, int),
            user_agent=_env("USER_AGENT", d.user_agent),
            contact=_env("CONTACT", d.contact),
            ollama_url=_env("OLLAMA_URL", d.ollama_url),
            default_model=_env("MODEL", d.default_model),
            ai_timeout=_env("AI_TIMEOUT", d.ai_timeout, float),
            ai_num_gpu=gpu,
            data_dir=Path(_env("DATA_DIR", str(d.data_dir))),
            redact_usernames=_env("REDACT_USERNAMES", "1") not in ("0", "false", "no"),
            web_port=_env("WEB_PORT", d.web_port, int),
        )
