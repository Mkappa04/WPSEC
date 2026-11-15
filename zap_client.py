#!/usr/bin/env python3
"""
Client minimale per l'API JSON di OWASP ZAP (solo libreria standard).

ZAP va avviato in modalità daemon, ad esempio (porta 8090 per non collidere con Burp su 8080):

  Docker (in WSL2):
    docker run -u zap -p 127.0.0.1:8090:8090 -i zaproxy/zap-stable zap.sh -daemon \
      -host 0.0.0.0 -port 8090 -config api.addrs.addr.name=.* \
      -config api.addrs.addr.regex=true -config api.key=LA_TUA_CHIAVE

  Programma installato:
    zap.sh -daemon -port 8090 -config api.key=LA_TUA_CHIAVE

La chiave si passa con --zap-key o con la variabile d'ambiente ZAP_API_KEY.
Questo modulo NON avvia mai scansioni attive da solo: lo decide l'agente (policy).
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

ZAP_URL_DEFAULT = "http://127.0.0.1:8090"


class ZapErrore(Exception):
    """Errore di comunicazione o risposta d'errore da ZAP."""


class ZapClient:
    def __init__(self, url=ZAP_URL_DEFAULT, apikey="", timeout=30):
        self.url = url.rstrip("/")
        self.apikey = apikey or os.environ.get("ZAP_API_KEY", "")
        self.timeout = timeout
        # ZAP è locale: mai passare da Burp o da proxy di sistema
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _chiama(self, componente, tipo, nome, **params):
        q = {k: v for k, v in params.items() if v is not None and v != ""}
        if self.apikey:
            q["apikey"] = self.apikey
        url = f"{self.url}/JSON/{componente}/{tipo}/{nome}/?{urllib.parse.urlencode(q)}"
        try:
            with self._opener.open(url, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            try:
                d = json.loads(e.read().decode("utf-8", errors="replace"))
                msg = f"{d.get('code', e.code)}: {d.get('message', '')}".strip()
            except Exception:
                msg = f"HTTP {e.code}"
            raise ZapErrore(f"{componente}/{nome}: {msg}")
        except Exception as e:
            raise ZapErrore(f"{componente}/{nome}: {e}")

    def versione(self):
        return self._chiama("core", "view", "version").get("version", "?")

    def nuova_sessione(self):
        self._chiama("core", "action", "newSession", name="", overwrite="true")

    def imposta_modalita(self, modalita="protect"):
        """protect: le scansioni attive sono permesse solo su URL nel contesto/scope."""
        self._chiama("core", "action", "setMode", mode=modalita)

    def imposta_user_agent(self, ua):
        """Facoltativo: non tutte le versioni lo supportano, quindi non è bloccante."""
        try:
            self._chiama("core", "action", "setOptionDefaultUserAgent", String=ua)
            return True
        except ZapErrore:
            return False

    def spider_non_invasivo(self):
        """
        Chiede allo spider di NON compilare e NON inviare moduli (niente commenti,
        ricerche o email di contatto generati per sbaglio sul sito analizzato).
        Ritorna l'elenco delle opzioni che ZAP non ha accettato (vuoto = tutto applicato).
        """
        rifiutate = []
        for opzione in ("setOptionPostForm", "setOptionProcessForm"):
            try:
                self._chiama("spider", "action", opzione, Boolean="false")
            except ZapErrore:
                rifiutate.append(opzione)
        return rifiutate

    def crea_contesto(self, nome, regex):
        """Limita lo scope: ZAP non toccherà URL fuori dalla regex."""
        try:
            self._chiama("context", "action", "removeContext", contextName=nome)
        except ZapErrore:
            pass
        self._chiama("context", "action", "newContext", contextName=nome)
        self._chiama("context", "action", "includeInContext", contextName=nome, regex=regex)

    def accedi(self, url):
        self._chiama("core", "action", "accessUrl", url=url, followRedirects="true")

    def spider(self, url, contesto="", max_children=30, timeout_s=120):
        """Esplora il sito. Ritorna (n_url_trovati, completato)."""
        r = self._chiama("spider", "action", "scan", url=url, contextName=contesto,
                         maxChildren=max_children, recurse="true")
        sid = r.get("scan")
        if sid is None:
            raise ZapErrore("spider: nessun id restituito")
        fine = time.time() + timeout_s
        completato = False
        while time.time() < fine:
            stato = int(self._chiama("spider", "view", "status", scanId=sid).get("status", 0))
            if stato >= 100:
                completato = True
                break
            time.sleep(1)
        if not completato:
            try:
                self._chiama("spider", "action", "stop", scanId=sid)
            except ZapErrore:
                pass
        risultati = self._chiama("spider", "view", "results", scanId=sid).get("results", [])
        return len(risultati), completato

    def attendi_pscan(self, timeout_s=120):
        """Attende che l'analisi passiva abbia finito. Ritorna True se completata."""
        fine = time.time() + timeout_s
        while time.time() < fine:
            if int(self._chiama("pscan", "view", "recordsToScan").get("recordsToScan", 0)) == 0:
                return True
            time.sleep(1)
        return False

    def avvisi(self, baseurl, massimo=500):
        return self._chiama("core", "view", "alerts", baseurl=baseurl, start=0,
                            count=massimo).get("alerts", [])

    def scansione_attiva(self, url, timeout_s=600):
        """Scansione attiva limitata allo scope. Ritorna True se completata, False se interrotta."""
        r = self._chiama("ascan", "action", "scan", url=url, recurse="true", inScopeOnly="true")
        sid = r.get("scan")
        if sid is None:
            raise ZapErrore("ascan: nessun id restituito")
        fine = time.time() + timeout_s
        while time.time() < fine:
            stato = int(self._chiama("ascan", "view", "status", scanId=sid).get("status", 0))
            if stato >= 100:
                return True
            time.sleep(2)
        try:
            self._chiama("ascan", "action", "stop", scanId=sid)
        except ZapErrore:
            pass
        return False


def trova_zap(url=None, apikey="", candidati_host=None):
    """
    Cerca ZAP. Con url esplicito usa solo quello; altrimenti prova 127.0.0.1 e, su WSL2,
    l'IP dell'host Windows (candidati_host). Ritorna (ZapClient, versione) oppure (None, errore).
    """
    if url:
        urls = [url]
    else:
        hosts = candidati_host or ["127.0.0.1"]
        urls = [f"http://{h}:8090" for h in hosts]
    ultimo = "nessun indirizzo provato"
    for u in urls:
        c = ZapClient(u, apikey, timeout=3)
        try:
            v = c.versione()
            c.timeout = 30
            return c, v
        except ZapErrore as e:
            ultimo = f"{u} -> {e}"
    return None, ultimo
