"""Migrazioni dello schema. Eseguite dentro la transazione di apertura dell'archivio:
se qualcosa fallisce, il database resta com'era.

v1 -> v2: lo schema v1 conservava il risultato completo in `scans.data`. Le tabelle v2
vengono ricostruite da quel JSON, quindi nessun dato va perso. Le autorizzazioni hanno
la stessa struttura e restano dove sono.
"""

from __future__ import annotations

import sqlite3
from typing import Callable

from wpsec.core.models import ScanResult
from wpsec.database.schema import STATEMENTS_V2


def migrate_v1_to_v2(c: sqlite3.Connection, write_scan: Callable[[sqlite3.Connection, ScanResult], None]) -> int:
    rows = c.execute("SELECT data FROM scans").fetchall()
    results = [ScanResult.model_validate_json(r["data"]) for r in rows]
    c.execute("DROP TABLE IF EXISTS findings")
    c.execute("DROP TABLE IF EXISTS scans")
    for stmt in STATEMENTS_V2:
        c.execute(stmt)
    # in ordine cronologico; le scansioni rimaste "running" non vengono sigillate e saranno
    # marcate come interrotte all'avvio dell'interfaccia (mark_interrupted)
    for r in sorted(results, key=lambda x: x.started_at):
        write_scan(c, r)
    return len(results)
