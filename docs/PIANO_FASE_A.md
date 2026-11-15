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
| `wpsec/config/settings.py` | Scritto, non testato |
| `wpsec/core/models.py` | Scritto, non testato |
| `wpsec/core/context.py` | Scritto, non testato |
| `wpsec/scanner/probes.py`, `http_client.py` | Scritti, non testati |
| `wpsec/scanner/wordpress_checks.py`, `security_headers.py`, `tls_checks.py`, `fingerprint.py` | Scritti, non testati |
| `wpsec/knowledge/catalog.py`, `remediation.py` | Scritti (CWE da ricontrollare su cwe.mitre.org) |
| `wpsec/ai/prompts.py`, `validator.py`, `ollama_client.py`, `interface.py` | Scritti, non testati |
| `wpsec/integrations/network.py` | Scritto, non testato |
| `wpsec/agents/base.py`, `reconnaissance_agent.py` | Scritti, non testati |
| `tests/helpers.py` | Funzioni di supporto per i test |
| `wpsec/ai/assistant.py` | **Da scrivere** (implementazione di `AIProvider`) |
| Agenti HTTP Security, WordPress, Evidence, Risk, Remediation, Reporting, ZAP | **Da scrivere** |
| Orchestratore e pianificatore | **Da scrivere** |
| Database SQLite, report, confronto, API FastAPI, dashboard, CLI `main.py` | **Da scrivere** |
| Test dei moduli v4, documentazione in `docs/` | **Da scrivere** |

Verifiche eseguite finora: solo i 6 test di caratterizzazione della v3 (passano).

## 6. Prossimi passi consigliati

1. Test dei moduli già scritti (client HTTP, analisi delle risposte, contesto).
2. Agenti mancanti e orchestratore.
3. Database, report, confronto.
4. API e dashboard.
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
