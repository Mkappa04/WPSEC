# WPSEC

Piattaforma per la valutazione **non invasiva** della sicurezza di siti WordPress, sviluppata
come progetto universitario. Analizza soltanto siti per cui esiste un'autorizzazione registrata
(o il laboratorio locale) e invia solo richieste in lettura: nessun login, exploit, brute force
o test di iniezione.

## 1. Panoramica

WPSEC esegue una serie di controlli su un sito WordPress (utenti esposti, versione visibile,
XML-RPC, directory listing, header di sicurezza HTTP e altri). Ogni risultato viene confermato
solo se è sostenuto da un'evidenza, cioè una richiesta HTTP effettivamente eseguita e
registrata. Un modello linguistico locale (Ollama), se disponibile, aggiunge spiegazioni e una
sintesi, ma non decide gli esiti.

La dashboard web locale permette di:

- consultare lo **storico** delle scansioni, con sito, data, stato e numero di problemi;
- aprire il **dettaglio** di una scansione: riepilogo, problemi confermati con le relative
  evidenze, correzioni suggerite e attività di ciascun agente;
- aprire o scaricare i **report** in HTML, PDF, Markdown e JSON, anche in versione anonimizzata;
- **confrontare** due scansioni dello stesso sito (prima/dopo una correzione) e vedere quali
  problemi sono nuovi, risolti o ancora presenti;
- seguire l'**andamento** dei problemi di un sito nel tempo.

## 2. Avvio rapido

Prerequisiti: **Python 3.10 o successivo** (indicato in `pyproject.toml`; verificato con
3.10.12) e Git. I comandi seguenti sono per Linux o WSL.

```bash
git clone https://github.com/Mkappa04/WPSEC.git
cd WPSEC

# su Ubuntu/Debian, se manca il modulo venv: sudo apt install python3-venv
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements-dev.txt   # dipendenze della dashboard + pytest (serve alla demo)
```

`requirements.txt` contiene solo ciò che serve alla piattaforma (FastAPI, Uvicorn, Pydantic,
fpdf2). `requirements-dev.txt` lo include e aggiunge gli strumenti di test, necessari anche
allo script dei dati dimostrativi descritto più avanti.

Avvio della dashboard:

```bash
python main.py serve
```

Il comando stampa `Dashboard: http://127.0.0.1:8000/`: aprire quell'indirizzo nel browser.
Il server ascolta solo in locale e si ferma con `Ctrl+C`.

Per usare un'altra porta:

```bash
python main.py serve --port 8010
```

In alternativa si può impostare la variabile d'ambiente `WPSEC_WEB_PORT`.

Senza altre opzioni i dati (database SQLite e report) vengono salvati in `./data`. L'opzione
globale `--data-dir`, scritta **prima** del comando, sceglie un'altra cartella:
`python main.py --data-dir data/demo serve`.

## 3. Demo per il tutor

La demo usa solo dati fittizi: siti WordPress simulati in locale, senza Internet, Docker o
Ollama. Conviene tenerla in una cartella separata (`data/demo`), che Git ignora.

### Caricare i dati dimostrativi

```bash
python lab/demo_dashboard.py --data-dir data/demo
```

Lo script avvia per pochi secondi dei siti WordPress simulati (`lab/mock_wp.py`) e un finto
Ollama, esegue le scansioni e le salva nell'archivio. Vengono creati:

- tre scansioni dello stesso sito, etichettate `iniziale`, `prima` e `dopo`. Fra una e
  l'altra alcuni problemi vengono corretti e uno compare, così il confronto ha rilievi nuovi,
  risolti e ancora presenti;
- una scansione di un sito "ingannevole" (`tricky`), con un controllo da verificare a mano e
  un falso positivo scartato;
- una scansione di un sito protetto (`protetto`);
- le due scansioni della versione precedente (v3) presenti in `scansioni/`, importate.

Lo script si rifiuta di scrivere in una cartella non vuota. Per ricominciare, cancellare
`data/demo` e rilanciarlo.

Avviare poi la dashboard su quell'archivio:

```bash
python main.py --data-dir data/demo serve
```

e aprire `http://127.0.0.1:8000`.

### Percorso consigliato nella dashboard

1. **Storico.** Dal menu a sinistra (in alto, su schermi piccoli) scegliere *Storico*. Ogni
   riga mostra sito, data, stato e problemi confermati; con il filtro *Sito* si restringe
   l'elenco a un solo sito.
2. **Dettaglio.** Cliccare il sito della scansione con etichetta `dopo`. L'intestazione indica
   sempre il record aperto (ID, data, etichetta). Le schede sono:
   - *Riepilogo*: conteggi e problemi confermati;
   - *Rilievi*: ogni problema con le evidenze, cioè la richiesta eseguita, il codice HTTP e un
     estratto della risposta;
   - *Agenti*: cosa ha fatto ciascun agente.
3. **Report.** Nella scheda *Report*:
   - *Apri il report* apre la versione HTML in una nuova scheda;
   - *Scarica* salva il PDF, il Markdown o il JSON;
   - *Scarica anonimizzato* o *Versione anonimizzata* produce la stessa cosa senza dati
     identificativi.
4. **Confronto.** Dal menu scegliere *Confronto*, impostare *Prima* sulla scansione `prima` e
   *Dopo* sulla scansione `dopo`, poi premere *Confronta*. Il risultato atteso è:
   - 1 problema **nuovo** (directory listing in uploads);
   - 3 **risolti** (utenti via REST API, enumerazione autori, versione esposta);
   - 6 **ancora presenti** (header di sicurezza).

   *Scarica il confronto in Markdown* salva il confronto.
5. **Andamento.** *Andamento* mostra quanti problemi sono confermati in ciascuna delle tre
   scansioni del sito, con una tabella problema per problema.

### Senza lo script: solo le scansioni v3

Se lo script non è utilizzabile, si possono importare le due scansioni del laboratorio salvate
dalla versione precedente. Basta `requirements.txt`:

```bash
python main.py --data-dir data/demo-v3 import-v3 scansioni/127.0.0.1_8081_*.json
python main.py --data-dir data/demo-v3 serve
```

Storico, dettaglio e report funzionano allo stesso modo. Il confronto fra queste due scansioni
mostra solo problemi ancora presenti e un avviso: le scansioni v3 non erano validate da
evidenze, per cui il confronto è meno significativo.

### Le stesse operazioni da riga di comando

```bash
python main.py --data-dir data/demo list                          # storico
python main.py --data-dir data/demo report <ID> --formats html,pdf # report in data/demo/reports
python main.py --data-dir data/demo compare <ID-prima> <ID-dopo>   # confronto
```

Gli ID delle scansioni (`scan-…`) compaiono nell'output di `list`.

### Scansioni reali sul laboratorio

Per scansioni su un vero WordPress serve il laboratorio Docker in `lab/` (`lab/lab.sh` e
`lab/docker-compose.yml`: tre siti sulle porte 8081-8083). Per esempio:

```bash
python main.py scan --lab http://127.0.0.1:8081 --label prima --no-ai
```

Non è necessario per la demo della dashboard.

## 4. Tecnologie e strumenti

| Componente | Ruolo |
|---|---|
| **Python** | Linguaggio di tutta la piattaforma (pacchetto `wpsec/`). Gli agenti specializzati sono: ricognizione, controlli WordPress, header HTTP, validazione delle evidenze, valutazione del rischio, correzioni e report. Un orchestratore li coordina. Tutte le richieste passano da un client HTTP che rispetta il perimetro dell'autorizzazione. |
| **FastAPI** (con Uvicorn) | API REST e server della dashboard (`wpsec/web/app.py`). Accetta solo host locali, applica controlli contro le richieste da altri siti e una Content-Security-Policy restrittiva. |
| **SQLite** | Archivio locale (`data/wpsec.sqlite3`): autorizzazioni, scansioni, evidenze, risultati e cronologia degli stati. Le scansioni concluse non sono più modificabili. |
| **HTML, CSS, JavaScript** | Dashboard in `wpsec/web/static/`. File locali, senza CDN né librerie esterne. I dati entrano nella pagina solo come testo, mai come HTML. |
| **Pydantic** | Modelli dei dati e validazione delle richieste all'API. |
| **fpdf2** | Generazione dei report PDF. |
| **Ollama** | Esegue in locale il modello linguistico. Il modello predefinito è `qwen3.5:4b` (`default_model` in `wpsec/config/settings.py`; si cambia con `WPSEC_MODEL` o con `scan --model`). Il modello scrive spiegazioni, contesto delle correzioni e sintesi. Con il pianificatore sperimentale (`scan --planner llm`) propone anche l'**ordine** dei controlli previsti, ma non può aggiungerne, toglierne o confermarne l'esito. |

**Ollama non serve per la demo.** La consultazione di storico, dettagli, report e confronti
non lo usa, e lo script demo usa un finto Ollama interno. Senza Ollama la pagina *Nuova
scansione* indica "Ollama non raggiungibile" e le scansioni procedono senza spiegazioni
dell'IA.

**Strumenti di sviluppo.**

- **Claude Code** è stato usato come supporto allo sviluppo: scrittura e revisione del codice,
  test, benchmark e documentazione.
- **Playwright** è stato usato il 18/11/2026 per verificare la dashboard in un browser
  Chromium, a 1440 e 390 px di larghezza. Sono stati provati storico, dettaglio, apertura e
  download dei report, confronto, andamento, stati vuoti e di errore e navigazione da
  tastiera. Gli script di quella verifica non fanno parte del repository.

## 5. Stato del progetto

Verifiche documentate:

- **Test automatici.** `pytest` esegue 269 test di unità e di integrazione. I test usano siti
  simulati e un finto Ollama, quindi non richiedono Internet né Ollama.

  ```bash
  python -m pytest
  ```

- **Ground truth del laboratorio.** Lo stato reale dei tre siti Docker è stato verificato a
  mano il 17/11/2026 ed è registrato in `lab/ground_truth.json`.
- **Benchmark.** Lo script è `lab/benchmark_v4.py`. Risultati e dettagli sono nella sezione 9
  di `docs/PIANO_FASE_A.md` e in `lab/risultati_benchmark/benchmark_v4_20261118_144226.md`.

Riepilogo del benchmark del 18/11/2026 (3 siti del laboratorio, 2 ripetizioni, modello
`qwen3.5:4b`):

| Configurazione | Precisione | Richiamo | Tempo medio per scansione |
|---|---|---|---|
| v3 (versione precedente) | 1,0 | 0,769 | 0,5 s |
| v4 senza IA | 1,0 | 1,0 | 0,14 s |
| v4 con IA (`v4-ia`) | 1,0 | 1,0 | 63 s |
| v4 con pianificatore LLM (`v4-llm`) | 1,0 | 1,0 | 67 s |

Per `v4-llm` il pianificatore ha preso 12 decisioni, tutte valide, senza mai dover tornare
all'ordine fisso. Delle 108 chiamate al modello, 95 hanno dato una risposta valida. Le altre
sono state scartate senza conseguenze sugli esiti: manca solo la spiegazione. L'IA allunga i
tempi ma non cambia i risultati.

Limiti dichiarati: i siti del benchmark sono tre e nessuno usa HTTPS, quindi i controlli HSTS,
cookie e redirect HTTPS risultano non applicabili. Il comportamento dietro un WAF è coperto
solo dai siti simulati nei test.

Lavori aperti (da `docs/PIANO_FASE_A.md`): l'agente per l'analisi passiva con OWASP ZAP e i
documenti `METHODOLOGY.md` e `DEVELOPMENT_LOG.md`.

## Struttura del repository

```
main.py                 riga di comando (auth, scan, list, report, compare, import-v3, serve…)
wpsec/                  piattaforma v4: agenti, orchestratore, archivio, report, API e dashboard
lab/                    laboratorio Docker, siti simulati, benchmark, script dei dati demo
tests/                  test automatici
docs/                   piano del progetto e schema del database
scansioni/              scansioni del laboratorio salvate dalla versione precedente (v3)
Pentest_ollama_v2.py    versione precedente (v3), conservata per i test e il benchmark
```
