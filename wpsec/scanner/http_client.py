"""Client HTTP con perimetro: l'UNICO punto da cui la piattaforma contatta il target.

Garanzie applicate dal codice (non dall'IA):
  1. solo sonde del registro chiuso (probes.py): nessun URL o corpo libero;
  2. ogni origine (schema, host, porta) deve essere nel perimetro dell'autorizzazione;
  3. protezione SSRF: l'host viene risolto e gli indirizzi non pubblici sono rifiutati
     (loopback e reti private solo con autorizzazione di laboratorio); la connessione
     va all'IP appena verificato, quindi un DNS rebinding non può cambiarlo;
  4. redirect seguiti a mano, uno per uno, ciascuno ricontrollato contro il perimetro;
  5. pausa minima tra le richieste, budget massimo per scansione, timeout,
     dimensione massima della risposta, annullamento cooperativo;
  6. cache delle GET: la stessa risorsa non viene richiesta due volte;
  7. Burp solo se configurato esplicitamente; in quel caso il report lo dichiara.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlsplit

from wpsec.config.settings import Settings
from wpsec.core.models import Authorization, Evidence, Origin
from wpsec.scanner.probes import Probe, get_probe

REDIRECT_CODES = {301, 302, 303, 307, 308}
Resolver = Callable[[str, int], list[str]]


class ScopeError(Exception):
    """Richiesta fuori dal perimetro autorizzato."""


class BudgetExceeded(Exception):
    """Superato il numero massimo di richieste per la scansione."""


class Cancelled(Exception):
    """Scansione annullata (timeout dell'agente o richiesta dell'utente)."""


def default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


def ip_block_reason(ip_text: str, allow_private: bool) -> str | None:
    """Motivo per cui l'IP non è contattabile, oppure None se è ammesso."""
    ip = ipaddress.ip_address(ip_text.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return f"indirizzo non utilizzabile ({ip})"
    if ip.is_link_local:   # comprende 169.254.169.254 (metadati cloud): sempre vietato
        return f"indirizzo link-local vietato ({ip})"
    if ip.is_loopback or ip.is_private:
        return None if allow_private else (
            f"indirizzo locale/privato ({ip}) non ammesso: serve un'autorizzazione di laboratorio")
    if not ip.is_global:
        return f"indirizzo non pubblico ({ip})"
    return None


@dataclass(frozen=True)
class ProxyConfig:
    host: str
    port: int

    @classmethod
    def parse(cls, text: str) -> "ProxyConfig":
        host, _, port = text.strip().rpartition(":")
        if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("formato atteso host:porta, ad esempio 127.0.0.1:8080")
        ip = ipaddress.ip_address(host)  # solo IP letterali: niente risoluzioni DNS per il proxy
        if not (ip.is_loopback or ip.is_private):
            raise ValueError("il proxy deve essere locale (loopback o gateway WSL2)")
        return cls(host, int(port))

    @property
    def label(self) -> str:
        return f"Burp {self.host}:{self.port} (TLS non verificato)"


@dataclass
class HttpResponse:
    probe_id: str
    method: str
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    body: str = ""
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    redirect_blocked: str = ""
    error: str | None = None
    scope_blocked: bool = False
    elapsed_s: float = 0.0
    evidence: Evidence | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def mask_cookie(raw: str) -> str:
    """'sessione=abc123; Path=/; HttpOnly' -> 'sessione=***; Path=/; HttpOnly'."""
    name, _, rest = raw.partition("=")
    _, sep, attrs = rest.partition(";")
    return f"{name.strip()}=***" + (f";{attrs}" if sep else "")


class ScopedHttpClient:
    def __init__(self, authorization: Authorization, target: Origin, settings: Settings,
                 proxy: ProxyConfig | None = None, resolver: Resolver | None = None,
                 cancel_event: threading.Event | None = None):
        if not authorization.covers(target):
            raise ScopeError(f"{target.url} non è nel perimetro dell'autorizzazione {authorization.id}")
        self.auth = authorization
        self.target = target
        self.settings = settings
        self.proxy = proxy
        self.resolver = resolver or default_resolver
        self.cancel_event = cancel_event or threading.Event()
        self._lock = threading.Lock()
        self._last_request = 0.0
        self._cache: dict[tuple, HttpResponse] = {}
        self.stats = {"requests": 0, "cache_hits": 0, "blocked": 0, "errors": 0}
        self.on_evidence: Callable[[Evidence], None] | None = None

    # ------------------------------------------------------------------ API
    @property
    def network_mode(self) -> str:
        return f"Via {self.proxy.label}" if self.proxy else "Diretta (TLS verificato)"

    def probe(self, probe_id: str, *, fresh: bool = False) -> HttpResponse:
        """Esegue una sonda del registro. fresh=True ignora la cache (ricontrollo)."""
        probe = get_probe(probe_id)
        origin = self.target
        if probe.scheme and probe.scheme != origin.scheme:
            origin = Origin(scheme=probe.scheme, host=origin.host,
                            port=80 if probe.scheme == "http" else 443)
        key = (probe.method, origin, probe.path, probe.body)
        if probe.cacheable and not fresh and key in self._cache:
            self.stats["cache_hits"] += 1
            cached = self._cache[key]
            ev = cached.evidence.model_copy(update={"from_cache": True}) if cached.evidence else None
            return HttpResponse(**{**cached.__dict__, "evidence": ev})
        resp = self._execute(probe, origin)
        resp.evidence = self._make_evidence(probe, resp, recheck=fresh)
        if self.on_evidence:
            self.on_evidence(resp.evidence)
        if probe.cacheable and resp.ok:
            self._cache[key] = resp
        return resp

    def resolve_checked(self, origin: Origin) -> str:
        """Risolve l'host del perimetro e restituisce un IP ammesso (usato anche dai controlli TLS)."""
        if not self.auth.covers(origin):
            raise ScopeError(f"{origin.url} fuori perimetro")
        try:
            ips = self.resolver(origin.host, origin.port)
        except OSError as e:
            raise ScopeError(f"risoluzione DNS fallita per {origin.host}: {e}") from e
        if not ips:
            raise ScopeError(f"nessun indirizzo per {origin.host}")
        for ip in ips:  # TUTTI gli indirizzi devono essere ammessi (niente risposte miste)
            reason = ip_block_reason(ip, self.auth.allow_private_addresses)
            if reason:
                raise ScopeError(reason)
        return ips[0]

    def tls_inspect(self):
        """Un handshake TLS verso il target (sempre diretto, mai via Burp)."""
        from wpsec.scanner.tls_checks import inspect_tls
        if self.target.scheme != "https":
            raise ValueError("target non HTTPS")
        ip = self.resolve_checked(self.target)
        self._throttle()
        return inspect_tls(self.target.host, self.target.port, ip, self.settings.request_timeout)

    def check_cancelled(self):
        if self.cancel_event.is_set():
            raise Cancelled("scansione annullata")

    # ------------------------------------------------------------ interno
    def _throttle(self):
        with self._lock:
            self.check_cancelled()
            if self.stats["requests"] >= self.settings.max_requests:
                raise BudgetExceeded(f"budget di {self.settings.max_requests} richieste esaurito")
            wait = self.settings.min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()
            self.stats["requests"] += 1

    def _execute(self, probe: Probe, origin: Origin) -> HttpResponse:
        url = origin.url + probe.path
        resp = HttpResponse(probe.id, probe.method, url, final_url=url)
        t0 = time.monotonic()
        method, body, path, current = probe.method, probe.body, probe.path, origin
        try:
            for hop in range(self.settings.max_redirects + 1):
                # perimetro + SSRF a OGNI salto (anche con Burp, che però risolve per conto suo)
                ip = self.resolve_checked(current)
                status, headers, cookies, text = self._send_once(
                    current, None if self.proxy else ip, method, path, body, probe.headers)
                resp.status, resp.headers, resp.set_cookies, resp.body = status, headers, cookies, text
                resp.final_url = current.url + path
                location = headers.get("location")
                if status not in REDIRECT_CODES or not location or not probe.follow_redirects:
                    break
                if hop == self.settings.max_redirects:
                    resp.error = f"troppi redirect (>{self.settings.max_redirects})"
                    break
                nxt = urljoin(current.url + path, location)
                try:
                    nxt_origin = Origin.from_url(nxt)
                except ValueError:
                    resp.redirect_blocked = nxt[:300]
                    break
                if not self.auth.covers(nxt_origin):
                    resp.redirect_blocked = nxt[:300]
                    self.stats["blocked"] += 1
                    break
                resp.redirect_chain.append(nxt)
                sp = urlsplit(nxt)
                current, path = nxt_origin, (sp.path or "/") + (f"?{sp.query}" if sp.query else "")
                if status in (301, 302, 303):
                    method, body = "GET", None
        except ScopeError as e:
            resp.error, resp.scope_blocked = f"bloccato: {e}", True
            self.stats["blocked"] += 1
        except (BudgetExceeded, Cancelled) as e:
            resp.error = str(e)
        except ssl.SSLCertVerificationError as e:
            resp.error = f"certificato TLS non valido: {e.verify_message or e}"
        except (socket.timeout, TimeoutError):
            resp.error = f"timeout dopo {self.settings.request_timeout}s"
        except (OSError, http.client.HTTPException) as e:
            resp.error = f"errore di rete: {e.__class__.__name__}: {e}"
        if resp.error:
            self.stats["errors"] += 1
        resp.elapsed_s = max(round(time.monotonic() - t0, 3), 0.001)
        return resp

    def _send_once(self, origin: Origin, ip: str | None, method: str, path: str,
                   body: bytes | None, extra_headers: dict[str, str]):
        self._throttle()
        timeout = self.settings.request_timeout
        if self.proxy:
            if origin.scheme == "https":
                ctx = ssl._create_unverified_context()  # Burp presenta il proprio certificato
                conn = http.client.HTTPSConnection(self.proxy.host, self.proxy.port,
                                                   timeout=timeout, context=ctx)
                conn.set_tunnel(origin.host, origin.port)
                target = path
            else:
                conn = http.client.HTTPConnection(self.proxy.host, self.proxy.port, timeout=timeout)
                target = origin.url + path
        elif origin.scheme == "https":
            conn = _PinnedHTTPSConnection(origin.host, origin.port, ip, timeout,
                                          ssl.create_default_context())
            target = path
        else:
            conn = _PinnedHTTPConnection(origin.host, origin.port, ip, timeout)
            target = path
        headers = {"User-Agent": self.settings.effective_user_agent, "Accept": "*/*",
                   "Connection": "close", **extra_headers}
        try:
            conn.request(method, target, body=body, headers=headers)
            r = conn.getresponse()
            raw = r.read(self.settings.max_body_bytes)
            hdrs: dict[str, str] = {}
            cookies: list[str] = []
            for k, v in r.getheaders():
                k = k.lower()
                if k == "set-cookie":
                    cookies.append(v)
                hdrs[k] = f"{hdrs[k]}, {v}" if k in hdrs else v
            return r.status, hdrs, cookies, raw.decode("utf-8", errors="replace")
        finally:
            conn.close()

    def _make_evidence(self, probe: Probe, resp: HttpResponse, recheck: bool) -> Evidence:
        headers = {k: v for k, v in resp.headers.items() if k != "set-cookie"}
        if resp.set_cookies:
            headers["set-cookie"] = " | ".join(mask_cookie(c) for c in resp.set_cookies)
        raw = resp.body.encode("utf-8", errors="replace")
        return Evidence(
            probe_id=probe.id, method=probe.method, url=resp.url, status_code=resp.status,
            headers=headers, body_sha256=hashlib.sha256(raw).hexdigest() if raw else "",
            body_length=len(raw), final_url=resp.final_url, redirect_chain=resp.redirect_chain,
            redirect_blocked=resp.redirect_blocked, elapsed_s=resp.elapsed_s, error=resp.error,
            via_proxy=self.proxy.label if self.proxy else "", recheck=recheck)
