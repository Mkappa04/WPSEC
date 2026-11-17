# Piano architetturale (Fase A) e stato dei lavori

Documento di passaggio fra sessioni di lavoro. Riassume l'analisi della Fase A,
le decisioni prese e lo stato reale del codice.

## 1. Decisioni prese

- **ZAP**: solo analisi passiva; la scansione attiva è ammessa unicamente con
  un'autorizzazione di tipo laboratorio (127.0.0.1). Per i siti remoti è eliminata.
- **Lingua**: identificatori del codice in inglese; interfaccia e documentazione in italiano.
- **Git**: repository inizializzato; lo stato originale è nel primo commit (`361e222`).
- **Storico**: le scansioni di `aternos.org` in `scansioni/` sono escluse dall'importazione
  (nessuna autorizzazione documentata). I dati del laboratorio e dei siti autorizzati vanno
  anonimizzati prima dell'uso nella tesi.
- **Commit**: si fanno solo dopo conferma esplicita dello studente.

## 2. Principio guida

Il codice decide cosa si fa (quali richieste, quali controlli, quando un risultato è
confermato); l'IA locale spiega e contestualizza, ma non può inviare richieste né
confermare risultati senza evidenze. È un'architettura ad agenti specializzati con IA in
alcuni agenti, non un sistema di agenti autonomi.

Motivazione sperimentale (dati reali in `lab/risultati_benchmark/`): con l'IA come
pianificatore, diversi run hanno avuto decisioni non valide e ricorso all'ordine fisso in
15 run su 15; nei run solo CPU la copertura è scesa a 0,667 (richiamo 0,7), contro 1,0
dell'ordine fisso.

## 3. Problemi principali della v3 (sintesi)

| Area | Problema |
|---|---|
| Sicurezza | Redirect seguiti senza controllo del perimetro; nessuna protezione SSRF; qualunque servizio sulla porta 8080 trattato come Burp con TLS non verificato; autorizzazione ridotta a un sì/no; sito reale come target predefinito; comando di shell a ogni richiesta; username conservati in chiaro |
| Correttezza | Solo due esiti (manca "inconcludente"); esposizione e vulnerabilità confuse; header aggregati in un solo risultato; falso positivo sul directory listing; versione cercata solo nel meta generator; percorso alternativo degli utenti non provato in caso di errore; home scaricata 3 volte; il confronto dichiara "risolto" anche un blocco del WAF |
| Architettura | Stato globale modificabile condiviso fra script; codice duplicato; nessun test, nessun `requirements.txt` |

I test in `tests/regression/test_legacy_characterization.py` documentano gli esiti della v3,
compresi i tre errori noti sul sito simulato `wp-tricky`.

## 4. Architettura

```
Authorization + ScanRequest
        │
  ORCHESTRATOR (deterministico: dipendenze, timeout, errori isolati, traccia)
        │
  Recon ──▶ WordPress Agent / HTTP Security Agent
        │       (scrivono Observation + Evidence nello ScanContext)
        ▼
  Evidence Validation ──▶ Risk Assessment ──▶ Remediation ──▶ Reporting
        │
  Tutte le richieste passano solo da ScopedHttpClient + registro chiuso delle sonde
```

Ciclo di vita di un risultato: `candidate | not_detected | error` →
`confirmed | false_positive | inconclusive | not_present | not_applicable`.
Le transizioni ammesse sono in `wpsec/core/models.py` e applicate da `wpsec/core/context.py`.

## 5. Stato del codice

| Modulo | Stato |
|---|---|
| `wpsec/config/settings.py` | Scritto, usato dai test |
| `wpsec/core/models.py` | Scritto e testato (`tests/unit/test_models.py`) |
| `wpsec/core/context.py` | Scritto e testato (`tests/unit/test_context.py`) |
| `wpsec/scanner/probes.py`, `http_client.py` | Scritti e testati (`tests/integration/test_http_client.py`) |
| `wpsec/scanner/wordpress_checks.py`, `security_headers.py`, `tls_checks.py`, `fingerprint.py` | Scritti e testati (`tests/unit/`) |
| `wpsec/knowledge/catalog.py`, `remediation.py` | Scritti (CWE da ricontrollare su cwe.mitre.org) |
| `wpsec/ai/prompts.py`, `validator.py`, `ollama_client.py`, `interface.py` | Scritti, testati tramite `assistant.py` e il finto Ollama |
| `wpsec/ai/assistant.py` | Scritto e testato (`OllamaAssistant`: validazione, tentativi, disattivazione se Ollama è spento) |
| `wpsec/integrations/network.py` | Scritto, non testato |
| `wpsec/agents/`: Recon, WordPress, HTTP Security, Evidence Validation, Risk, Remediation, Reporting | Scritti e testati (`tests/unit/test_evidence_and_risk.py`, `test_http_security_agent.py`, `tests/integration/test_scan_pipeline.py`) |
| `wpsec/core/orchestrator.py` | Scritto e testato (`tests/unit/test_orchestrator.py`): ordine topologico per fasi, requisiti, errori isolati, timeout per agente, annullamento, pianificatore LLM sperimentale (solo ordine, mai salto di controlli, ricorso all'ordine fisso) |
| `wpsec/core/scan.py` | Scritto e testato: `run_scan()` con controlli preliminari (`ScanRefused`) prima di qualunque richiesta |
| `tests/helpers.py` | Funzioni di supporto per i test |
| Agente ZAP (analisi passiva) | **Da scrivere** (`run_scan` per ora rifiuta `use_zap`) |
| `wpsec/database/schema.py`, `store.py`, `migrations.py` | Schema v2 scritto e testato (`docs/DATABASE.md`): tabelle normalizzate per scansioni, agenti, evidenze, risultati, cronologia degli stati, note IA, correzioni (template versionati), traccia; JSON completo come archivio; sigillo di immutabilità con trigger SQL; vista `finding_timeline` per l'andamento nel tempo; migrazione automatica dalla v1 |
| `wpsec/database/legacy.py` | Scritto e testato: importazione delle scansioni v3; solo loopback o host dichiarati autorizzati, `aternos.org` sempre rifiutato, username mascherati |
| `wpsec/comparison/compare.py` | Scritto e testato: "risolto" solo se confermato prima e assenza verificata dopo; inconcludente/errore/non applicabile = NON CONFRONTABILE (corregge la v3); confronto v3↔v4 per `legacy_id` con header aggregati |
| `wpsec/reports/` | Scritto e testato: JSON, Markdown, HTML autonomo (escape + CSP senza script), PDF (fpdf2, DejaVu o ripiego Latin-1); IA sempre marcata; anonimizzazione per la tesi |
| `wpsec/core/authorization.py` | Scritto e testato: creazione validata (laboratorio solo loopback; sito reale con documento obbligatorio, niente scansione attiva, massimo 90 giorni) |
| `wpsec/web/app.py`, `scan_manager.py`, `static/` | Scritti e testati: API FastAPI + dashboard (JS locale, solo `textContent`), scansioni in background con limite di concorrenza e annullamento; protezioni: Host locali (DNS rebinding), Origin e corpo JSON (CSRF), CSP senza inline, report serviti in sandbox |
| `main.py` | Scritto e testato: CLI `auth`, `scan` (anche `--lab URL`), `list`, `report`, `compare`, `import-v3`, `models`, `serve` (solo locale salvo `--allow-remote`) |
| Documentazione in `docs/` (METHODOLOGY.md, DEVELOPMENT_LOG.md citati nel codice) | **Da scrivere** |

Verifiche eseguite finora: 250 test passano (6 di caratterizzazione v3 + 244 dei moduli v4),
copertura circa 92%. Prova manuale sul laboratorio Docker (WordPress reale, porte 8081-8083):
vedi la sezione 8. Sul sito simulato `wp-tricky` la pipeline v4 corregge i tre
errori noti della v3: utenti dietro il 403 del WAF -> inconcludente (non "protetto"),
versione esposta nel feed -> confermata, "Index of" in un articolo -> falso positivo.

## 6. Prossimi passi consigliati

1. ~~Test dei moduli già scritti (client HTTP, analisi delle risposte, contesto).~~ **Fatto.**
2. ~~Agenti mancanti e orchestratore.~~ **Fatto** (manca solo l'agente ZAP).
3. ~~Database, report, confronto.~~ **Fatto.**
4. ~~API e dashboard.~~ **Fatto** (dashboard non ancora provata in un browser).
5. Benchmark sul laboratorio e documentazione.

## 7. Pianificazione delle 375 ore

| Fase | Ore |
|---|---|
| 1. Analisi e progettazione | 35 |
| 2. Refactoring e modularizzazione | 55 |
| 3. Architettura multi-agente | 85 |
| 4. Integrazione Ollama e gestione delle evidenze | 45 |
| 5. Dashboard e reporting | 55 |
| 6. Testing, sicurezza e valutazione | 45 |
| 7. Documentazione e presentazione | 55 |
| **Totale** | **375** |

Il dettaglio delle attività per fase è nella conversazione della Fase A; le ore reali vanno
registrate in `docs/DEVELOPMENT_LOG.md`.

## 8. Differenze fra v4 e `lab/ground_truth.json` sul laboratorio reale (17/11/2026)

La ground truth è scritta con la semantica della v3. Sul WordPress reale la v4 dà:

| Bersaglio | Controllo | Ground truth (v3) | v4 | Motivo |
|---|---|---|---|---|
| wp-hard, wp-mixed | versione | PROTETTO | confermato (confidenza media) | la versione 6.9.4 resta nel `?ver=` degli script di `wp-includes`; il generator è stato rimosso, ma l'esposizione c'è |
| wp-hard | header | PROTETTO | CSP confermato come *debole* | il CSP contiene `'unsafe-inline'`; la v3 controllava solo la presenza dell'header |
| tutti | header informativi | (non previsto) | confermato | `Server: Apache/2.4.67 (Debian)`, `X-Powered-By: PHP/8.3.31` |

Da decidere prima del benchmark (punto 5): aggiornare la ground truth alla semantica v4
(consigliato, motivando ogni cambio) oppure confrontare con la v3 solo sui controlli comuni.
