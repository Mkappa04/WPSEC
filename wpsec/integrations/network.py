"""Utilità di rete locali (WSL2, rilevamento di Burp) senza comandi di shell.

La v3 eseguiva `ip route ... | awk` con shell=True a OGNI richiesta HTTP; qui il
gateway di WSL2 si legge da /proc/net/route, una sola volta.
"""

from __future__ import annotations

import functools
import socket
import struct


@functools.lru_cache(maxsize=1)
def wsl_gateway() -> str | None:
    """IP del gateway predefinito (l'host Windows in WSL2), o None."""
    try:
        with open("/proc/net/route", encoding="ascii") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
    except (OSError, ValueError, StopIteration):
        return None
    return None


def port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def burp_candidates(port: int = 8080) -> list[str]:
    """Indirizzi su cui risponde qualcosa sulla porta di Burp. È SOLO un suggerimento
    per l'interfaccia: Burp si usa unicamente se l'utente lo sceglie esplicitamente."""
    hosts = ["127.0.0.1"]
    gw = wsl_gateway()
    if gw:
        hosts.append(gw)
    return [f"{h}:{port}" for h in hosts if port_open(h, port)]
