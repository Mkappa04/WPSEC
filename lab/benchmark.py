#!/usr/bin/env python3
"""
Benchmark dello scanner (pipeline) o dell'agente contro la ground truth del laboratorio.

Per ogni controllo, ogni bersaglio e OGNI ripetizione confronta l'esito con quello atteso
(ground_truth.json) e calcola:
  TP       atteso VULNERABILE, trovato VULNERABILE
  TN       atteso PROTETTO,    trovato PROTETTO
  FP       atteso PROTETTO,    trovato VULNERABILE   (falso allarme)
  FN       atteso VULNERABILE, trovato altro         (problema non rilevato)
  ERR      controllo andato in errore di rete
  SALT-FN  (solo agente) controllo NON eseguito, ma c'era un problema: problema perso
  SALT-OK  (solo agente) controllo NON eseguito e non c'era nulla da trovare
Più precisione, richiamo, F1, stabilità tra ripetizioni e tempi. Per l'agente anche:
passi, richieste HTTP, decisioni non valide dell'IA, ricorso all'ordine fisso (ripiego).

Uso:
  python3 benchmark.py                               # pipeline, 3 ripetizioni
  python3 benchmark.py --motore agente               # agente guidato da Ollama
  python3 benchmark.py --motore agente --politica fissa   # agente senza IA (riferimento)
  python3 benchmark.py --motore agente --modello llama3.2 -n 5
Codice di uscita 0 se non ci sono FP/FN/ERR/SALT-FN, 1 altrimenti.
"""

import argparse
import json
import os
import statistics
from collections import Counter
import sys
import time
from datetime import datetime
from pathlib import Path

QUI = Path(__file__).resolve().parent
sys.path.insert(0, str(QUI.parent))       # trova Pentest_ollama_v2.py e agente.py nella cartella superiore
sys.path.insert(0, str(QUI))
import Pentest_ollama_v2 as scanner  # noqa: E402

CLASSI = ("TP", "TN", "FP", "FN", "ERR", "SALT-FN", "SALT-OK")
SBAGLIATE = ("FP", "FN", "ERR", "SALT-FN")


def esegui_pipeline(url, a):
    """Esegue tutti i controlli una volta. Ritorna (dict id->finding, secondi, statistiche)."""
    t0 = time.time()
    r0 = scanner.STATISTICHE["richieste"]
    ris = {}
    for controllo in scanner.CONTROLLI:
        f = controllo(url)
        ris[f["id"]] = f
    return ris, round(time.time() - t0, 3), {"richieste_scanner": scanner.STATISTICHE["richieste"] - r0}


def esegui_agente(url, a):
    import agente
    t0 = time.time()
    esito = agente.esegui_agente(url, a.modello, a.politica, a.max_passi, a.completa,
                                 mostra=lambda *x, **k: None)
    return {f["id"]: f for f in esito["risultati"]}, round(time.time() - t0, 3), esito["stat"]


def classifica(atteso, trovato):
    if trovato == "NON ESEGUITO":
        return "SALT-FN" if atteso == "VULNERABILE" else "SALT-OK"
    if trovato == "ERRORE":
        return "ERR"
    if atteso == "VULNERABILE":
        return "TP" if trovato == "VULNERABILE" else "FN"
    return "FP" if trovato == "VULNERABILE" else "TN"


def conteggio(valori):
    """['TP','TP','SALT-FN'] -> 'TP x2, SALT-FN x1' (oppure solo 'TP' se tutti uguali)."""
    c = Counter(valori)
    if len(c) == 1:
        return valori[0]
    return ", ".join(f"{k} x{v}" for k, v in c.most_common())


def rapporto(a, b):
    return round(a / b, 3) if b else None


def media(valori):
    return round(statistics.mean(valori), 2) if valori else None


def main():
    ap = argparse.ArgumentParser(description="Benchmark scanner/agente vs ground truth")
    ap.add_argument("-n", "--ripetizioni", type=int, default=3)
    ap.add_argument("--motore", choices=["pipeline", "agente"], default="pipeline")
    ap.add_argument("--politica", choices=["llm", "fissa"], default="llm", help="solo per --motore agente")
    ap.add_argument("--modello", default=scanner.MODELLO_DEFAULT, help="solo per --motore agente")
    ap.add_argument("--max-passi", type=int, default=12, help="solo per --motore agente")
    ap.add_argument("--completa", action="store_true", help="solo agente: completa i controlli dopo 'fine'")
    ap.add_argument("--verita", default=str(QUI / "ground_truth.json"))
    ap.add_argument("--con-burp", action="store_true",
                    help="usa Burp se rilevato (di default è escluso per non sporcare i tempi)")
    ap.add_argument("--solo", help="nome di un solo bersaglio (es. wp-vuln)")
    ap.add_argument("--out", default=str(QUI / "risultati_benchmark"))
    a = ap.parse_args()

    scanner.PAUSA_TRA_RICHIESTE = 0   # il laboratorio è locale: nessun rate limit da rispettare
    if not a.con_burp:
        scanner.trova_host_burp = lambda *args, **kw: None
    esegui = esegui_agente if a.motore == "agente" else esegui_pipeline
    descr = a.motore + (f" ({a.politica}" + (f", {a.modello}" if a.politica == "llm" else "") + ")"
                        if a.motore == "agente" else "")
    if a.motore == "agente" and a.politica == "llm" and os.environ.get("PENTEST_NUM_GPU") == "0":
        descr += " [solo CPU]"

    gt = json.loads(Path(a.verita).read_text(encoding="utf-8"))
    bersagli = [b for b in gt["bersagli"] if not a.solo or b["nome"] == a.solo]

    tot = dict.fromkeys(CLASSI, 0)
    dettaglio, tempi, instabili, stat_run = [], {}, [], []
    print(f"=== BENCHMARK {descr}: {a.ripetizioni} ripetizioni, {'con' if a.con_burp else 'senza'} Burp ===")

    for b in bersagli:
        esiti = {cid: [] for cid in b["atteso"]}
        tempi_b, ultimo, visti = [], {}, set()
        for _ in range(a.ripetizioni):
            ris, sec, st = esegui(b["url"], a)
            tempi_b.append(sec)
            stat_run.append(st)
            ultimo = ris
            visti |= {cid for cid, f in ris.items() if f["esito"] != "INFO"}
            for cid in b["atteso"]:
                esiti[cid].append(ris[cid]["esito"] if cid in ris else "NON ESEGUITO")
        tempi[b["nome"]] = tempi_b

        # Ogni ripetizione conta: con l'agente l'IA può saltare controlli diversi
        # a ogni run, e guardare solo l'ultima nasconderebbe i problemi persi.
        for cid, atteso in b["atteso"].items():
            serie = esiti[cid]
            if len(set(serie)) > 1:
                instabili.append((b["nome"], cid, serie))
            classi = [classifica(atteso, t) for t in serie]
            for c in classi:
                tot[c] += 1
            peggiore = next((c for c in SBAGLIATE if c in classi), classi[-1])
            dettaglio.append({"bersaglio": b["nome"], "controllo": cid, "atteso": atteso,
                              "trovato": conteggio(serie), "classe": conteggio(classi),
                              "esiti_per_run": serie, "classe_peggiore": peggiore,
                              "evidenza": ultimo.get(cid, {}).get("evidenza", "controllo non eseguito")})
        extra = visti - set(b["atteso"])
        if extra:
            print(f"  [!] {b['nome']}: controlli senza ground truth (ignorati): {sorted(extra)}")

    # ---- metriche
    persi = tot["FN"] + tot["ERR"] + tot["SALT-FN"]
    prec = rapporto(tot["TP"], tot["TP"] + tot["FP"])
    ric = rapporto(tot["TP"], tot["TP"] + persi)
    f1 = rapporto(2 * prec * ric, prec + ric) if prec and ric else None
    tutti_tempi = [t for v in tempi.values() for t in v]
    n_ok = tot["TP"] + tot["TN"] + tot["SALT-OK"]
    n_tot = sum(tot.values())
    efficienza = {"richieste_medie": media([s.get("richieste_scanner", 0) for s in stat_run])}
    if a.motore == "agente":
        efficienza.update({
            "passi_medi": media([s["passi"] for s in stat_run]),
            "chiamate_ia_medie": media([s["chiamate_llm"] for s in stat_run]),
            "decisioni_non_valide_totali": sum(s["decisioni_invalide"] for s in stat_run),
            "run_con_ripiego": sum(1 for s in stat_run if s["ripiego"]),
            "riavvii_modello": sum(s.get("riavvii_modello", 0) for s in stat_run),
            "azioni_normalizzate": sum(s.get("azioni_normalizzate", 0) for s in stat_run),
            "tempo_ia_medio_s": media([s["tempo_llm_s"] for s in stat_run]),
            "run_totali": len(stat_run),
        })

    motivi_invalidi = Counter(e[:120] for s in stat_run for e in s.get("errori_ia", []))

    # ---- stampa
    print(f"\n(conteggi su tutte le {a.ripetizioni} ripetizioni)")
    print(f"{'Bersaglio':<10} {'Controllo':<10} {'Atteso':<12} {'Trovato':<32} Classe")
    for d in dettaglio:
        segno = "  <--" if d["classe_peggiore"] in SBAGLIATE else ""
        print(f"{d['bersaglio']:<10} {d['controllo']:<10} {d['atteso']:<12} {d['trovato']:<32} {d['classe']}{segno}")
    print("\n" + " ".join(f"{c}={tot[c]}" for c in CLASSI if tot[c] or c in ("TP", "TN", "FP", "FN")))
    eseguiti = n_tot - tot["SALT-FN"] - tot["SALT-OK"]
    print(f"Copertura: {eseguiti}/{n_tot} controlli eseguiti ({rapporto(eseguiti, n_tot)})")
    print(f"Accuratezza: {n_ok}/{n_tot}   Precisione: {prec}   Richiamo: {ric}   F1: {f1}")
    if tutti_tempi:
        sd = statistics.pstdev(tutti_tempi) if len(tutti_tempi) > 1 else 0.0
        print(f"Tempo per scansione completa: media {statistics.mean(tutti_tempi):.2f}s, "
              f"dev.std {sd:.2f}s, max {max(tutti_tempi):.2f}s")
    print("Efficienza: " + ", ".join(f"{k}={v}" for k, v in efficienza.items()))
    if motivi_invalidi:
        print("\nPerché le decisioni dell'IA non erano valide (più frequenti):")
        for motivo, n in motivi_invalidi.most_common(5):
            print(f"  {n:>3} x  {motivo}")
    if instabili:
        print("\nControlli INSTABILI (esito diverso tra ripetizioni):")
        for nome, cid, serie in instabili:
            print(f"  {nome}/{cid}: {serie}")
    else:
        print("Stabilità: esiti identici in tutte le ripetizioni.")
    errori = [d for d in dettaglio if d["classe_peggiore"] in SBAGLIATE]
    for d in errori:
        print(f"  - {d['bersaglio']}/{d['controllo']} [{d['classe']}]: {d['evidenza']}")

    # ---- salvataggio
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    sigla = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:19]
    nome_file = f"benchmark_{a.motore}_{sigla}"
    riepilogo = {"data": datetime.now().isoformat(timespec="seconds"), "motore": descr,
                 "ripetizioni": a.ripetizioni, "con_burp": a.con_burp, "conteggi": tot,
                 "accuratezza": rapporto(n_ok, n_tot),
                 "copertura": rapporto(n_tot - tot["SALT-FN"] - tot["SALT-OK"], n_tot), "precisione": prec, "richiamo": ric, "f1": f1,
                 "efficienza": efficienza, "tempi_s": tempi,
                 "motivi_decisioni_non_valide": dict(motivi_invalidi.most_common()),
                 "instabili": [{"bersaglio": n, "controllo": c, "esiti": s} for n, c, s in instabili],
                 "dettaglio": dettaglio}
    (out / f"{nome_file}.json").write_text(json.dumps(riepilogo, ensure_ascii=False, indent=2), encoding="utf-8")
    md = [f"# Benchmark {descr} ({riepilogo['data']})", "",
          f"- Ripetizioni: {a.ripetizioni} | Burp: {'sì' if a.con_burp else 'no'}",
          "- " + " ".join(f"{c}={tot[c]}" for c in CLASSI),
          f"- Conteggi su tutte le ripetizioni | Copertura {riepilogo['copertura']}",
          f"- Accuratezza {riepilogo['accuratezza']} | Precisione {prec} | Richiamo {ric} | F1 {f1}",
          "- Efficienza: " + ", ".join(f"{k}={v}" for k, v in efficienza.items()), ""]
    if motivi_invalidi:
        md += ["## Motivi delle decisioni non valide dell'IA", ""]
        md += [f"- {n} x {m}" for m, n in motivi_invalidi.most_common()]
        md += [""]
    md += [
          "| Bersaglio | Controllo | Atteso | Trovato | Classe |", "|---|---|---|---|---|"]
    md += [f"| {d['bersaglio']} | {d['controllo']} | {d['atteso']} | {d['trovato']} | {d['classe']} |" for d in dettaglio]
    (out / f"{nome_file}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"\n[OK] Salvati in {out}/{nome_file}.(json|md)")
    return 0 if not errori else 1


if __name__ == "__main__":
    sys.exit(main())
