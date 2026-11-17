# Archivio dei dati (SQLite, schema v2)

File: `data/wpsec.sqlite3` (cartella configurabile con `--data-dir` o `WPSEC_DATA_DIR`).
Codice: `wpsec/database/schema.py` (definizione), `store.py` (accesso), `migrations.py`.

## 1. Requisiti

| Requisito | Come è soddisfatto |
|---|---|
| Storico delle scansioni | `scans` con indice (host, data); elenco, coppia più recente, cancellazione |
| Vulnerabilità rilevate | `findings` con tutti i campi del ciclo di vita e della valutazione del rischio |
| Evidenze | `evidence` (una riga per richiesta realmente eseguita) e `finding_evidence` (quali evidenze sostengono quale risultato) |
| Remediation | `remediation_templates` versionati per `catalog_version` + `finding_remediation` |
| Confronto nel tempo | confronto fra due scansioni (`wpsec/comparison`) e vista `finding_timeline` (andamento di ogni problema) |
| Tracciabilità delle decisioni | `status_history` (ogni cambio di stato con agente, motivo, evidenze), `ai_notes`, `trace_events` |

## 2. Schema

```
authorizations ──< scans ──< agent_runs
                     ├──< evidence ───────────────┐
                     ├──< findings ──< finding_evidence  (molti-a-molti)
                     │       ├──< status_history
                     │       ├──< ai_notes
                     │       └──  finding_remediation ──> remediation_templates
                     └──< trace_events                    (template_id, catalog_version)
vista finding_timeline
```

| Tabella | Chiave | Contenuto principale |
|---|---|---|
| `authorizations` | `id` | tipo (`lab`/`engagement`), target, chi autorizza, validità, revoca, JSON completo |
| `scans` | `id` | autorizzazione, host, target, stato, origine (`v4`/`legacy-v3`), date, versioni di piattaforma e catalogo, rete, modello IA, pianificatore, conteggi, sintesi, `sealed`, `raw_result` |
| `agent_runs` | (`scan_id`, `name`) | stato, tempi, richieste, risultati, messaggio/errore di ciascun agente |
| `evidence` | `id` | sonda, metodo, URL, stato HTTP, header minimizzati, SHA-256 e lunghezza del corpo, estratto, redirect, errore, proxy, cache, ricontrollo |
| `findings` | `id`, unico (`scan_id`, `check_id`) | controllo, id v3, `tracking_key`, titolo, categoria, tipo, stato, confidenza, percorso, sintesi, dettagli, gravità, priorità, impatto, probabilità, motivazione, CWE, CVSS |
| `finding_evidence` | (`finding_id`, `evidence_id`) | collegamento molti-a-molti (la home sostiene più risultati) |
| `status_history` | (`finding_id`, `seq`) | da → a, agente, motivo, evidenze usate, ora |
| `ai_notes` | (`finding_id`, `seq`) | modello, scopo, testo, priorità suggerita, versione del prompt, tentativi |
| `remediation_templates` | (`template_id`, `catalog_version`) | copia del template com'era in quella versione del catalogo |
| `finding_remediation` | `finding_id` | template e versione applicati, contesto dell'IA, riferimenti |
| `trace_events` | (`scan_id`, `seq`) | traccia di orchestratore e pianificatore |

**`tracking_key`** = `check_id|percorso`: identifica lo stesso problema in scansioni diverse dello
stesso host. È la base della vista `finding_timeline` e di `Store.issue_timeline()`
(prima e ultima conferma, numero di conferme, riaperture dopo una correzione).

## 3. Integrità applicata dal database

- **Chiavi esterne** (`PRAGMA foreign_keys = ON`): cancellare una scansione cancella tutte le sue
  righe; le autorizzazioni non si cancellano (`ON DELETE RESTRICT`), si revocano.
- **CHECK** su stati dei risultati e degli agenti, gravità, priorità, confidenza, origine.
- **Sigillo**: una scansione terminata (`completed`, `failed`, `cancelled`) viene sigillata
  (`sealed = 1`). Trigger SQL rifiutano da quel momento ogni modifica alla scansione e alle sue
  righe figlie; resta possibile solo cancellarla per intero. Il risultato archiviato è quindi
  quello prodotto dalla scansione, non modificabile a posteriori.
- **Template versionati**: un template di correzione non si modifica (trigger). Se il catalogo
  cambia il testo senza cambiare `CATALOG_VERSION`, il salvataggio fallisce (`TemplateConflict`):
  i vecchi report restano ricostruibili.
- **Minimizzazione**: il corpo delle risposte non ha una colonna; si salvano hash, lunghezza
  ed estratto minimo. Gli username sono mascherati prima di arrivare all'archivio.

## 4. Flusso

1. **Durante la scansione** (al massimo una volta al secondo): si aggiornano solo la riga di
   `scans` (stato, conteggi, istantanea JSON) e `agent_runs`. Serve all'avanzamento nella dashboard.
2. **A fine scansione**, in una sola transazione (`BEGIN IMMEDIATE`): `raw_result`, poi
   `evidence`, `findings`, `finding_evidence`, `status_history`, `ai_notes`,
   `remediation_templates` (se la versione manca), `finding_remediation`, `trace_events`; infine
   il sigillo. Se qualcosa fallisce non resta nulla di parziale.
3. **Lettura**: report e confronto ricostruiscono lo `ScanResult` da `raw_result` (stesso
   risultato prodotto dalla scansione); elenchi, storico, evidenze e metriche usano SQL.
4. **Avvio dell'interfaccia**: le scansioni rimaste in corso (processo terminato) diventano
   `failed` con il motivo e vengono sigillate.

### Perché tenere anche il JSON completo

- **Riproducibilità**: report e confronti si rigenerano identici anche dopo cambi di schema.
- **Migrazioni sicure**: le tabelle si ricostruiscono dal JSON (così è avvenuta la v1 → v2).
- Costo: spazio su disco (decine di KB per scansione), trascurabile per l'uso previsto.

### Perché i confronti non sono salvati

Il confronto è deterministico e si calcola da due scansioni sigillate: salvarlo duplicherebbe
dati derivati da tenere allineati. Il Markdown del confronto si può salvare su file
(`main.py compare --save`) quando serve come allegato.

## 5. Migrazioni

`PRAGMA user_version` contiene la versione dello schema. All'apertura:
- versione 0 (nuovo): creazione dello schema v2;
- versione 1: `migrate_v1_to_v2` ricostruisce tutte le tabelle dal JSON delle scansioni, nella
  stessa transazione dell'apertura (se fallisce il database resta in v1);
- versione maggiore di quella supportata: errore (database creato da una versione più recente).

## 6. Interrogazioni utili

```sql
-- problemi ancora aperti per host, con prima comparsa
SELECT host, title, MIN(started_at) AS prima_volta, COUNT(*) AS conferme
FROM finding_timeline WHERE status = 'confirmed' GROUP BY host, tracking_key;

-- quali richieste hanno confermato un risultato
SELECT e.method, e.url, e.status_code, e.body_sha256
FROM finding_evidence fe JOIN evidence e ON e.id = fe.evidence_id WHERE fe.finding_id = ?;

-- quante decisioni ha ribaltato la validazione (es. falsi positivi scartati)
SELECT to_status, COUNT(*) FROM status_history WHERE agent = 'evidence' GROUP BY to_status;
```
