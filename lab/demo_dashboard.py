#!/usr/bin/env python3
"""Dati di prova per la dashboard: un archivio con sole scansioni dei siti simulati.

Crea in --data-dir (vuota) un archivio con:
  - un'autorizzazione di laboratorio per ogni sito simulato;
  - tre scansioni dello stesso sito (iniziale, prima, dopo) fra le quali alcuni problemi
    vengono corretti e uno compare: il confronto prima/dopo ha rilievi nuovi, risolti e
    ancora presenti, e l'andamento ha tre punti;
  - una scansione del sito "tricky" (inconcludente e falso positivo) e una del sito protetto;
  - le scansioni v3 del laboratorio in scansioni/ (importate);
  - note e sintesi dell'IA da un finto Ollama (nessun modello reale).

Nessun dato di siti reali. Uso:
  python lab/demo_dashboard.py --data-dir /percorso/vuoto
  python main.py --data-dir /percorso/vuoto serve --port 8010
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

QUI = Path(__file__).resolve().parent
RADICE = QUI.parent
sys.path[:0] = [str(RADICE), str(QUI)]

import mock_wp  # noqa: E402
from tests.conftest import FakeOllama, _avvia  # noqa: E402
from tests.helpers import FAST, lab_auth  # noqa: E402
from wpsec.ai.assistant import OllamaAssistant  # noqa: E402
from wpsec.ai.ollama_client import OllamaClient  # noqa: E402
from wpsec.core.models import ScanOptions  # noqa: E402
from wpsec.core.scan import run_scan  # noqa: E402
from wpsec.database.legacy import import_legacy_scan  # noqa: E402
from wpsec.database.store import Store  # noqa: E402

RISPOSTA_IA = ('{"spiegazione": "Chi conosce gli username deve indovinare solo la password: '
               'il rischio cresce se non c\'è un limite ai tentativi di accesso.", '
               '"priorita": "media", "contesto": "La correzione riduce le informazioni utili '
               'a un attacco automatico.", "sintesi": "Il sito espone informazioni utili a un '
               'attaccante (utenti, versione) e manca di alcuni header di protezione. Nessun '
               'problema critico; le correzioni sono di configurazione e richiedono poche ore."}')

# (etichetta, correzioni applicate al sito simulato al momento della scansione)
SEQUENZA = [
    ("iniziale", {"uploads"}),
    ("prima", {"uploads", "xmlrpc"}),
    ("dopo", {"utenti", "author", "versione", "xmlrpc"}),   # uploads ricompare: nuovo
]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--data-dir", required=True, type=Path)
    a = p.parse_args(argv)
    if a.data_dir.exists() and any(a.data_dir.iterdir()):
        p.error(f"{a.data_dir} non è vuota: uso una cartella nuova per non toccare archivi esistenti")
    a.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(a.data_dir / "wpsec.sqlite3")

    fake = FakeOllama()
    fake.default = RISPOSTA_IA
    ai = OllamaAssistant(OllamaClient(fake.url, timeout=5), "qwen3.5:4b", FAST)

    # un solo indirizzo per la sequenza: il sito viene "corretto" fra una scansione e l'altra
    srv = _avvia(mock_wp.fabbrica(set()))
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    auth = store.save_authorization(lab_auth(url, document_ref="Laboratorio Docker, dati di prova"))
    for label, fixes in SEQUENZA:
        srv.RequestHandlerClass = mock_wp.fabbrica(fixes)
        r = run_scan(url, auth, ScanOptions(use_ai=True, label=label), FAST, ai=ai)
        store.save_scan(r)
        print(f"{r.id}  {label:9} {url}  confermati: {sum(f.status.value == 'confirmed' for f in r.findings)}")
    srv.shutdown()

    for nome, fixes, tricky in (("tricky", set(mock_wp.PROFILI[8085]), True),
                                ("protetto", set(mock_wp.TUTTE), False)):
        s = _avvia(mock_wp.fabbrica(fixes, False, tricky))
        u = f"http://127.0.0.1:{s.server_address[1]}"
        au = store.save_authorization(lab_auth(u))
        r = run_scan(u, au, ScanOptions(use_ai=False, label=nome), FAST, ai=None)
        store.save_scan(r)
        print(f"{r.id}  {nome:9} {u}")
        s.shutdown()

    for f in sorted((RADICE / "scansioni").glob("127.0.0.1_*.json")):
        r = import_legacy_scan(f)
        store.save_scan(r)
        print(f"{r.id}  v3        {f.name}")
    fake.server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
