"""Esecuzione delle scansioni in background per l'interfaccia web.

- i controlli preliminari (autorizzazione, perimetro, opzioni) sono SINCRONI: se falliscono
  la richiesta HTTP riceve subito l'errore e nessuna scansione parte;
- al massimo settings.max_concurrent_scans scansioni contemporanee;
- l'avanzamento è letto dal contesto vivo (istantanea coerente) e salvato nell'archivio
  al massimo una volta al secondo; il risultato finale è sempre salvato;
- l'annullamento è cooperativo (cancel_event controllato dal client HTTP e dall'IA).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from wpsec.config.settings import Settings
from wpsec.core.models import ScanOptions, ScanResult, new_id
from wpsec.core.scan import AUTO, ScanRefused, preflight, run_scan
from wpsec.database.store import FINAL_STATES, NotFound, Store

SAVE_INTERVAL_S = 1.0


class Busy(Exception):
    """Troppe scansioni in corso."""


@dataclass
class _Running:
    scan_id: str
    target: str
    cancel_event: threading.Event = field(default_factory=threading.Event)
    ctx: object = None
    thread: threading.Thread | None = None
    last_save: float = 0.0
    done: threading.Event = field(default_factory=threading.Event)
    error: str = ""


class ScanManager:
    def __init__(self, store: Store, settings: Settings, ai=AUTO, resolver=None):
        self.store = store
        self.settings = settings
        self.ai = ai
        self.resolver = resolver
        self._lock = threading.Lock()
        self._running: dict[str, _Running] = {}

    # ------------------------------------------------------------ comandi
    def start(self, authorization_id: str, target_url: str, options: ScanOptions) -> str:
        auth = self.store.get_authorization(authorization_id)   # NotFound -> 404
        preflight(target_url, auth, options)                    # ScanRefused -> 400
        with self._lock:
            active = [r for r in self._running.values() if not r.done.is_set()]
            if len(active) >= self.settings.max_concurrent_scans:
                raise Busy(f"già {len(active)} scansioni in corso "
                           f"(massimo {self.settings.max_concurrent_scans})")
            run = _Running(scan_id=new_id("scan-"), target=target_url)
            self._running[run.scan_id] = run

        def work():
            try:
                result = run_scan(target_url, auth, options, self.settings, ai=self.ai,
                                  resolver=self.resolver, cancel_event=run.cancel_event,
                                  on_update=lambda ctx: self._on_update(run, ctx),
                                  scan_id=run.scan_id)
                self.store.save_scan(result)
            except ScanRefused as e:      # es. autorizzazione scaduta fra start e avvio
                run.error = str(e)
            except Exception as e:        # non deve mai restare "running" per sempre
                run.error = f"{e.__class__.__name__}: {e}"
                if run.ctx is not None:
                    snap = run.ctx.snapshot()
                    snap.status, snap.error = "failed", run.error
                    self.store.save_scan(snap)
            finally:
                run.done.set()

        run.thread = threading.Thread(target=work, name=f"scan-{run.scan_id}", daemon=True)
        run.thread.start()
        return run.scan_id

    def cancel(self, scan_id: str) -> bool:
        run = self._running.get(scan_id)
        if run is None or run.done.is_set():
            return False
        run.cancel_event.set()
        return True

    def wait(self, scan_id: str, timeout: float | None = None) -> bool:
        run = self._running.get(scan_id)
        return True if run is None else run.done.wait(timeout)

    def shutdown(self, timeout: float = 5.0):
        for run in list(self._running.values()):
            run.cancel_event.set()
        for run in list(self._running.values()):
            run.done.wait(timeout)

    # ------------------------------------------------------------ lettura
    def is_running(self, scan_id: str) -> bool:
        run = self._running.get(scan_id)
        return run is not None and not run.done.is_set()

    def get(self, scan_id: str) -> ScanResult:
        run = self._running.get(scan_id)
        if run is not None and not run.done.is_set() and run.ctx is not None:
            return run.ctx.snapshot()
        try:
            return self.store.get_scan(scan_id)
        except NotFound:
            if run is not None and not run.done.is_set():
                raise NotFound(f"scansione {scan_id} in avvio") from None
            if run is not None and run.error:
                raise ScanRefused(run.error) from None
            raise

    def running(self) -> list[dict]:
        out = []
        for run in self._running.values():
            if run.done.is_set():
                continue
            snap = run.ctx.snapshot() if run.ctx is not None else None
            out.append({"id": run.scan_id, "target": run.target,
                        "agents": [{"name": a.name, "state": a.state.value} for a in snap.agents]
                        if snap else []})
        return out

    # ------------------------------------------------------------ interno
    def _on_update(self, run: _Running, ctx):
        run.ctx = ctx
        if ctx.result.status in FINAL_STATES:
            return  # il salvataggio finale (che sigilla la scansione) lo fa work()
        now = time.monotonic()
        if now - run.last_save >= SAVE_INTERVAL_S:
            run.last_save = now
            try:
                self.store.save_scan(ctx.snapshot())
            except Exception as e:  # l'archivio non deve fermare la scansione
                ctx.log("scan_manager", "save_error", str(e))
