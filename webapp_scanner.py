#!/usr/bin/env python3
"""
Web App locale per lo scanner WordPress (usa Pentest_ollama_v2.py).

Avvio:   python3 webapp_scanner_2.py
Poi apri http://127.0.0.1:8000 nel browser.

Il server ascolta SOLO su 127.0.0.1 (non è raggiungibile da altri computer),
perché deve parlare con Ollama e Burp che girano sul tuo PC.
Usare solo su siti per cui hai l'autorizzazione scritta del proprietario.
"""

import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import threading
import time
import urllib.parse
import urllib.request
import uuid

import Pentest_ollama_v2 as scanner

HOST, PORT = "127.0.0.1", 8000
HOST_OK = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
JOBS = {}
LOCK = threading.Lock()


# ---------------------------------------------------------------------
# Logica di scansione (in thread)
# ---------------------------------------------------------------------


def host_burp_corrente():
  """Ritorna l'IP dove risponde Burp (127.0.0.1 o gateway WSL2) o None."""
  porta = getattr(scanner, "PORTA_BURP", 8080)
  if hasattr(scanner, "trova_host_burp"):
    return scanner.trova_host_burp(porta)
  return (
      getattr(scanner, "HOST_BURP", "127.0.0.1")
      if scanner.burp_attivo()
      else None
  )


def modelli_ollama():
  """Cerca Ollama su 127.0.0.1 e, se presente in scanner, anche sul gateway WSL2."""
  candidati = ["127.0.0.1"]
  if hasattr(scanner, "_candidati_burp"):
    for h in scanner._candidati_burp():
      if h not in candidati:
        candidati.append(h)
  op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
  for h in candidati:
    try:
      with op.open(f"http://{h}:11434/api/tags", timeout=1.5) as r:
        dati = json.loads(r.read().decode())
        # Aggiorna dinamicamente l'URL di Ollama nello scanner se risponde sull'host Windows
        scanner.URL_OLLAMA = f"http://{h}:11434/api/generate"
        return [m["name"] for m in dati.get("models", [])]
    except Exception:
      continue
  return None


def csv_testo(risultati):
  buf = io.StringIO()
  w = csv.writer(buf)
  w.writerow([
      "ID",
      "Controllo",
      "Percorso",
      "Esito",
      "Gravità",
      "Priorità IA",
      "Evidenza",
      "Spiegazione IA",
      "Tempo (s)",
  ])
  for r in risultati:
    ia = r["ia"] or {}
    w.writerow([
        r["id"],
        r["titolo"],
        r["percorso"],
        r["esito"],
        r["gravita"],
        ia.get("priorita", ""),
        r["evidenza"],
        ia.get("spiegazione", ""),
        r["tempo"],
    ])
  return "\ufeff" + buf.getvalue()  # BOM per Excel


def esegui_scansione(job_id, base, modello, usa_ia):
  job = JOBS[job_id]
  try:
    for controllo in scanner.CONTROLLI:
      f = controllo(base)
      with LOCK:
        job["risultati"].append(f)
    problemi = [r for r in job["risultati"] if r["esito"] == "VULNERABILE"]
    if usa_ia and problemi:
      with LOCK:
        job["fase"] = "ia"
      for r in problemi:
        r["ia"] = scanner.analizza_con_ia(r, modello)
        if r["ia"] is None:
          job["ia_fallita"] = True
    hb = host_burp_corrente()
    porta_b = getattr(scanner, "PORTA_BURP", 8080)
    modo = f"Burp Proxy ({hb}:{porta_b})" if hb else "Diretta"
    job["report"] = scanner.costruisci_report(
        job["risultati"], base, modello if usa_ia else "IA disattivata", modo
    )
    job["csv"] = csv_testo(job["risultati"])
    try:
      scanner.salva_scansione(
          job["risultati"], base, modello if usa_ia else "IA disattivata", modo
      )
    except Exception:
      pass  # lo storico è un extra: non deve far fallire la scansione
    job["fase"] = "finito"
  except Exception as e:  # errore imprevisto: lo mostriamo all'utente
    job["fase"] = "errore"
    job["errore"] = str(e)


def stato_job(job):
  with LOCK:
    return {
        "fase": job["fase"],
        "totale": len(scanner.CONTROLLI),
        "completati": len(job["risultati"]),
        "ia_fallita": job.get("ia_fallita", False),
        "errore": job.get("errore"),
        "base": job["base"],
        "risultati": [
            {
                k: r[k]
                for k in (
                    "id",
                    "titolo",
                    "percorso",
                    "esito",
                    "gravita",
                    "evidenza",
                    "tempo",
                )
            }
            | {
                "ia": r["ia"],
                "fix": scanner.FIX.get(r["id"]) or r.get("soluzione") or "",
            }
            for r in job["risultati"]
        ],
    }


def url_valido(testo):
  testo = testo.strip()
  if not testo.startswith(("http://", "https://")):
    testo = "https://" + testo
  p = urllib.parse.urlparse(testo)
  if not p.hostname or " " in testo:
    return None
  return f"{p.scheme}://{p.netloc}"


# ---------------------------------------------------------------------
# Server HTTP
# ---------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
  server_version = "ScannerLocale/1.0"

  def log_message(self, *a):
    pass

  def _host_sicuro(self):
    """Protezione contro pagine web esterne che provano a usare il server locale."""
    if self.headers.get("Host", "") not in HOST_OK:
      return False
    origin = self.headers.get("Origin")
    if origin and origin.replace("http://", "") not in HOST_OK:
      return False
    return True

  def _invia(
      self, codice, corpo, tipo="application/json; charset=utf-8", extra=None
  ):
    dati = corpo if isinstance(corpo, bytes) else corpo.encode("utf-8")
    self.send_response(codice)
    self.send_header("Content-Type", tipo)
    self.send_header("Content-Length", str(len(dati)))
    self.send_header("Cache-Control", "no-store")
    self.send_header("X-Content-Type-Options", "nosniff")
    self.send_header("X-Frame-Options", "DENY")
    for k, v in (extra or {}).items():
      self.send_header(k, v)
    self.end_headers()
    self.wfile.write(dati)

  def _json(self, codice, obj):
    self._invia(codice, json.dumps(obj, ensure_ascii=False))

  def do_GET(self):
    if not self._host_sicuro():
      return self._json(403, {"errore": "Host non consentito"})
    path = urllib.parse.urlparse(self.path).path
    if path == "/":
      return self._invia(200, PAGINA, "text/html; charset=utf-8")
    if path == "/api/stato":
      m = modelli_ollama()
      hb = host_burp_corrente()
      porta_b = getattr(scanner, "PORTA_BURP", 8080)
      return self._json(
          200,
          {
              "burp": hb is not None,
              "burp_addr": f"{hb}:{porta_b}" if hb else f"porta {porta_b}",
              "ollama": m is not None,
              "modelli": m or [],
              "predefinito": scanner.MODELLO_DEFAULT,
          },
      )
    parti = path.strip("/").split("/")
    if len(parti) == 3 and parti[0] == "api" and parti[1] == "scan":
      job = JOBS.get(parti[2])
      if not job:
        return self._json(404, {"errore": "Scansione non trovata"})
      return self._json(200, stato_job(job))
    if len(parti) == 3 and parti[0] == "download":
      job = JOBS.get(parti[1])
      if not job or job["fase"] != "finito":
        return self._json(404, {"errore": "Report non pronto"})
      if parti[2] == "report.md":
        return self._invia(
            200,
            job["report"],
            "text/markdown; charset=utf-8",
            {
                "Content-Disposition": (
                    'attachment; filename="report_sicurezza_wp.md"'
                )
            },
        )
      if parti[2] == "dettaglio.csv":
        return self._invia(
            200,
            job["csv"],
            "text/csv; charset=utf-8",
            {
                "Content-Disposition": (
                    'attachment; filename="dettaglio_vulnerabilita_wp.csv"'
                )
            },
        )
    self._json(404, {"errore": "Non trovato"})

  def do_POST(self):
    if not self._host_sicuro():
      return self._json(403, {"errore": "Host non consentito"})
    if self.path != "/api/scan":
      return self._json(404, {"errore": "Non trovato"})
    try:
      n = int(self.headers.get("Content-Length", 0))
      dati = json.loads(self.rfile.read(min(n, 10_000)).decode())
    except Exception:
      return self._json(400, {"errore": "Richiesta non valida"})
    if dati.get("autorizzato") is not True:
      return self._json(
          400, {"errore": "Conferma di avere l'autorizzazione del proprietario"}
      )
    base = url_valido(str(dati.get("url", "")))
    if not base:
      return self._json(400, {"errore": "Indirizzo non valido"})
    modello = str(dati.get("modello") or scanner.MODELLO_DEFAULT)[:80]
    usa_ia = bool(dati.get("usa_ia", True))
    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "fase": "controlli",
        "base": base,
        "risultati": [],
        "ts": time.time(),
    }
    threading.Thread(
        target=esegui_scansione,
        args=(job_id, base, modello, usa_ia),
        daemon=True,
    ).start()
    self._json(200, {"id": job_id})


# ---------------------------------------------------------------------
# Interfaccia (HTML + CSS + JS in un unico file, nessuna risorsa esterna)
# ---------------------------------------------------------------------

PAGINA = r"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WP Security Scanner</title>
<style>
:root{
  --bg:#0f1220; --panel:#171b2e; --panel2:#1e2340; --line:#2a3053; --txt:#e8ebf7; --mut:#8e96ba;
  --acc:#6c8cff; --ok:#38c98a; --warn:#f2b441; --bad:#ff6b7a; --info:#6c8cff;
}
@media (prefers-color-scheme: light){
  :root{--bg:#f3f5fb;--panel:#fff;--panel2:#f0f2fa;--line:#dde1f0;--txt:#1b2040;--mut:#656d94;}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:32px 20px 64px}
header{display:flex;align-items:center;gap:14px;margin-bottom:24px}
.logo{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,var(--acc),#a06cff);display:grid;place-items:center;font-size:22px}
h1{font-size:22px;margin:0}
.sub{color:var(--mut);font-size:13px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin-bottom:16px}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.pill{display:flex;align-items:center;gap:6px;font-size:12px;padding:4px 10px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);color:var(--mut)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--mut)}
.dot.on{background:var(--ok)} .dot.off{background:var(--bad)}
label{display:block;font-size:13px;color:var(--mut);margin-bottom:6px}
.row{display:flex;gap:10px;flex-wrap:wrap}
input[type=text],select{background:var(--panel2);border:1px solid var(--line);color:var(--txt);border-radius:10px;padding:12px 14px;font-size:15px;outline:none}
input[type=text]{flex:1;min-width:220px}
input[type=text]:focus,select:focus{border-color:var(--acc)}
button{background:var(--acc);color:#fff;border:0;border-radius:10px;padding:12px 22px;font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
button.sec{background:var(--panel2);color:var(--txt);border:1px solid var(--line);font-weight:500;padding:9px 14px;font-size:13px}
.opts{display:flex;gap:18px;flex-wrap:wrap;margin-top:14px;align-items:center}
.chk{display:flex;gap:8px;align-items:flex-start;font-size:13px;color:var(--mut);cursor:pointer}
.chk input{margin-top:3px}
.err{color:var(--bad);font-size:13px;margin-top:10px;min-height:18px}
.bar{height:8px;background:var(--panel2);border-radius:99px;overflow:hidden;margin:12px 0 6px}
.bar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--acc),#a06cff);transition:width .3s}
.sum{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:6px}
.sum div{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:12px}
.sum b{display:block;font-size:24px}
.sum span{font-size:12px;color:var(--mut)}
.f{border:1px solid var(--line);border-radius:12px;margin-bottom:10px;background:var(--panel2);overflow:hidden}
.fh{display:flex;gap:10px;align-items:center;padding:12px 14px;cursor:pointer}
.fh .t{flex:1;font-weight:600}
.fh .p{color:var(--mut);font-size:12px;font-family:ui-monospace,Menlo,monospace}
.badge{font-size:11px;font-weight:700;padding:3px 9px;border-radius:99px;color:#fff}
.b-VULNERABILE{background:var(--bad)} .b-PROTETTO{background:var(--ok)} .b-ERRORE{background:var(--warn);color:#222} .b-INFO{background:var(--info)}
.sev{font-size:11px;color:var(--mut)}
.fb{display:none;padding:0 14px 14px;font-size:14px}
.f.open .fb{display:block}
.fb h4{margin:12px 0 4px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
.fb p{margin:0}
pre{background:#0b0e1b;color:#cfd6ff;border-radius:10px;padding:12px;overflow:auto;font-size:12.5px;margin:0;white-space:pre-wrap}
.ia{border-left:3px solid var(--acc);padding-left:10px}
.note{font-size:12px;color:var(--mut);margin-top:6px}
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--line);border-top-color:var(--acc);border-radius:50%;animation:r 1s linear infinite;vertical-align:-2px;margin-right:6px}
@keyframes r{to{transform:rotate(360deg)}}
.hide{display:none}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo">🛡️</div>
    <div>
      <h1>WP Security Scanner</h1>
      <div class="sub">Controlli non invasivi su WordPress + analisi con IA locale</div>
    </div>
  </header>

  <div class="pills">
    <div class="pill"><span class="dot" id="d-ollama"></span><span id="t-ollama">Ollama…</span></div>
    <div class="pill"><span class="dot" id="d-burp"></span><span id="t-burp">Burp…</span></div>
  </div>

  <div class="card">
    <label for="url">Indirizzo del sito da analizzare</label>
    <div class="row">
      <input type="text" id="url" placeholder="esempio.it oppure https://esempio.it" autocomplete="off">
      <button id="go">Avvia scansione</button>
    </div>
    <div class="opts">
      <div><label for="modello" style="margin:0 0 4px">Modello IA</label><select id="modello"></select></div>
      <label class="chk" style="margin-top:18px"><input type="checkbox" id="usaia" checked> Analisi con IA</label>
    </div>
    <label class="chk" style="margin-top:14px">
      <input type="checkbox" id="auth">
      <span>Confermo di avere l'<b>autorizzazione scritta</b> del proprietario del sito. Lo scanner fa solo richieste in sola lettura, senza brute force né exploit.</span>
    </label>
    <div class="err" id="err"></div>
  </div>

  <div class="card hide" id="prog">
    <div id="progtxt"><span class="spin"></span>Scansione in corso…</div>
    <div class="bar"><i id="barra"></i></div>
  </div>

  <div id="ris" class="hide">
    <div class="card">
      <div class="sum" id="sum"></div>
      <div class="row" style="margin-top:12px" id="dl"></div>
      <div class="note" id="nota"></div>
    </div>
    <div id="lista"></div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let timer = null;
let primoCaricamento = true;

async function caricaStato(){
  try{
    const s = await (await fetch("/api/stato")).json();
    $("d-ollama").className = "dot " + (s.ollama ? "on":"off");
    $("t-ollama").textContent = s.ollama ? "Ollama attivo" : "Ollama non raggiungibile";
    $("d-burp").className = "dot " + (s.burp ? "on":"off");
    $("t-burp").textContent = s.burp ? `Burp Suite in ascolto (${s.burp_addr})` : "Burp non attivo: connessione diretta";
    const sel = $("modello");
    const scelto = sel.value || s.predefinito;
    const lista = s.modelli.length ? s.modelli : [s.predefinito];
    if(primoCaricamento || sel.options.length !== lista.length){
      sel.innerHTML = lista.map(m => `<option ${m===scelto?"selected":""}>${esc(m)}</option>`).join("");
    }
    if(primoCaricamento && !s.ollama){ $("usaia").checked = false; }
    primoCaricamento = false;
  }catch(e){}
}

async function avvia(){
  $("err").textContent = "";
  const url = $("url").value.trim();
  if(!url){ $("err").textContent = "Inserisci l'indirizzo del sito."; return; }
  if(!$("auth").checked){ $("err").textContent = "Devi confermare di avere l'autorizzazione del proprietario."; return; }
  $("go").disabled = true;
  $("ris").classList.add("hide");
  $("prog").classList.remove("hide");
  $("barra").style.width = "3%";
  const r = await fetch("/api/scan", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({url, autorizzato:true, modello:$("modello").value, usa_ia:$("usaia").checked})});
  const d = await r.json();
  if(!r.ok){ $("err").textContent = d.errore || "Errore"; $("go").disabled=false; $("prog").classList.add("hide"); return; }
  clearInterval(timer);
  timer = setInterval(() => poll(d.id), 800);
  poll(d.id);
}

async function poll(id){
  const s = await (await fetch("/api/scan/" + id)).json();
  const tot = s.totale;
  let perc = Math.round(s.completati / tot * 85);
  if(s.fase === "ia") { perc = 90; $("progtxt").innerHTML = '<span class="spin"></span>L\'IA sta analizzando i problemi…'; }
  else if(s.fase === "controlli") $("progtxt").innerHTML = `<span class="spin"></span>Controlli ${s.completati}/${tot} su ${esc(s.base)}…`;
  $("barra").style.width = Math.max(perc, 3) + "%";
  mostra(s, id);
  if(s.fase === "finito" || s.fase === "errore"){
    clearInterval(timer); $("go").disabled = false;
    $("barra").style.width = "100%";
    setTimeout(() => $("prog").classList.add("hide"), 400);
    if(s.fase === "errore") $("err").textContent = "Errore: " + s.errore;
  }
}

function mostra(s, id){
  $("ris").classList.remove("hide");
  const v = s.risultati.filter(r => r.esito === "VULNERABILE").length;
  const p = s.risultati.filter(r => r.esito === "PROTETTO").length;
  const e = s.risultati.filter(r => r.esito === "ERRORE").length;
  $("sum").innerHTML =
    `<div><b>${s.risultati.length}</b><span>controlli eseguiti</span></div>` +
    `<div><b style="color:var(--bad)">${v}</b><span>problemi trovati</span></div>` +
    `<div><b style="color:var(--ok)">${p}</b><span>protetti</span></div>` +
    (e ? `<div><b style="color:var(--warn)">${e}</b><span>errori di rete</span></div>` : "");
  if(s.fase === "finito"){
    $("dl").innerHTML = `<a href="/download/${id}/report.md"><button class="sec">⬇ Report (Markdown)</button></a>` +
                        `<a href="/download/${id}/dettaglio.csv"><button class="sec">⬇ Dettagli (CSV)</button></a>`;
    $("nota").textContent = s.ia_fallita ? "Per alcuni problemi l'IA non ha risposto o ha dato un formato non valido: l'analisi è stata saltata." : "Le spiegazioni dell'IA sono indicative: vanno verificate da una persona.";
  }
  const aperti = new Set([...document.querySelectorAll(".f.open")].map(x => x.dataset.id));
  $("lista").innerHTML = s.risultati.map(r => {
    const ia = r.ia ? `<h4>Analisi IA (priorità ${esc(r.ia.priorita)})</h4><p class="ia">${esc(r.ia.spiegazione)}</p>` : "";
    const fix = (r.esito === "VULNERABILE" && r.fix) ? `<h4>Come correggere</h4><pre>${esc(r.fix)}</pre>` : "";
    return `<div class="f ${aperti.has(r.id) || (r.esito==='VULNERABILE' && aperti.size===0 && s.fase==='finito') ? "open":""}" data-id="${esc(r.id)}">
      <div class="fh" onclick="this.parentElement.classList.toggle('open')">
        <span class="badge b-${esc(r.esito)}">${esc(r.esito)}</span>
        <span class="t">${esc(r.titolo)}</span>
        ${r.gravita !== "-" ? `<span class="sev">${esc(r.gravita)}</span>` : ""}
        <span class="p">${esc(r.percorso)}</span>
      </div>
      <div class="fb"><h4>Evidenza</h4><p>${esc(r.evidenza)}</p>${ia}${fix}<div class="note">Tempo: ${esc(r.tempo)}s</div></div>
    </div>`;
  }).join("");
}

$("go").addEventListener("click", avvia);
$("url").addEventListener("keydown", e => { if(e.key === "Enter") avvia(); });
caricaStato();
setInterval(caricaStato, 5000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
  srv = ThreadingHTTPServer((HOST, PORT), Handler)
  print(f"Web App avviata su http://{HOST}:{PORT}  (Ctrl+C per fermare)")
  try:
    srv.serve_forever()
  except KeyboardInterrupt:
    print("\nChiuso.")