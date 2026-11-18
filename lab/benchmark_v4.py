#!/usr/bin/env python3
"""Benchmark della piattaforma v4 (e della v3 per confronto) contro la ground truth del laboratorio.

Configurazioni:
  v3       pipeline originale (Pentest_ollama_v2.py), solo i 6 controlli che conosceva
  v4       pipeline multi-agente, ordine fisso, senza IA
  v4-ia    come v4, con spiegazioni, contesto delle correzioni e sintesi dell'IA locale
  v4-llm   come v4-ia, con il pianificatore LLM (sceglie solo l'ordine dei controlli)

Classi per ogni controllo, bersaglio e ripetizione (ground truth v4: confirmed / not_present /
not_applicable):
  TP   atteso confirmed,    trovato confirmed
  TN   atteso not_present,  trovato not_present o false_positive (indicazione scartata)
  FP   atteso not_present,  trovato confirmed                    (falso allarme)
  FN   atteso confirmed,    trovato not_present / false_positive (problema perso)
  INC  trovato inconclusive (dichiarato "da verificare": non è un errore silenzioso, ma
       per il richiamo conta come problema non trovato)
  ERR  controllo in errore;  MISS  controllo non eseguito
  NA   atteso e trovato not_applicable;  NA-X  atteso not_applicable ma trovato altro
Metriche: precisione, richiamo, F1, accuratezza, copertura, stabilità, tempi, richieste,
statistiche dell'IA e del pianificatore.

Confronto equo v3/v4: oltre alle metriche complete della v4, tutte le configurazioni sono
valutate sui 6 controlli COMUNI (utenti, author, xmlrpc, versione, uploads, header aggregato)
rispetto alla STESSA ground truth v4 (stato reale verificato a mano).

Uso (dal laboratorio avviato con ./lab.sh su):
  python lab/benchmark_v4.py                         # v3 e v4, 3 ripetizioni
  python lab/benchmark_v4.py --configs all -n 2      # anche con IA (serve Ollama)
  python lab/benchmark_v4.py --configs v4 --solo wp-hard
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

QUI = Path(__file__).resolve().parent
RADICE = QUI.parent
sys.path[:0] = [str(RADICE), str(QUI)]

CLASSES = ("TP", "TN", "FP", "FN", "INC", "ERR", "MISS", "NA", "NA-X")
WRONG = ("FP", "FN", "ERR", "MISS", "NA-X")
CONFIGS = ("v3", "v4", "v4-ia", "v4-llm")
V3_STATUS = {"VULNERABILE": "confirmed", "PROTETTO": "not_present", "ERRORE": "error"}


# ================================================================== valutazione (funzioni pure)

def classify(expected: str, found: str | None) -> str:
    if expected == "not_applicable":
        return "NA" if found == "not_applicable" else "NA-X"
    if found is None:
        return "MISS"
    if found in ("error",):
        return "ERR"
    if found in ("inconclusive", "candidate", "not_detected"):
        return "INC"
    positive = found == "confirmed"
    if expected == "confirmed":
        return "TP" if positive else "FN"
    return "FP" if positive else "TN"


def aggregate(statuses: list[str | None]) -> str | None:
    """Esito unico di un gruppo di controlli (es. i sei header della v4 contro 'header' v3)."""
    known = [s for s in statuses if s is not None and s != "not_applicable"]
    if not known:
        return "not_applicable" if any(s == "not_applicable" for s in statuses) else None
    if "confirmed" in known:
        return "confirmed"
    for s in ("inconclusive", "error"):
        if s in known:
            return s
    return "not_present"


def common_view(statuses: dict[str, str], mapping: dict) -> dict[str, str | None]:
    """Dagli esiti v4 (per check_id) agli esiti sui controlli comuni (chiavi v3)."""
    out = {}
    for v3_id, target in mapping.items():
        ids = target if isinstance(target, list) else [target]
        out[v3_id] = aggregate([statuses.get(i) for i in ids])
    return out


def metrics(counts: Counter) -> dict:
    tp, fp = counts["TP"], counts["FP"]
    lost = counts["FN"] + counts["INC_POS"] + counts["ERR_POS"] + counts["MISS_POS"]
    total = sum(counts[c] for c in CLASSES)
    ok = counts["TP"] + counts["TN"] + counts["NA"]
    prec = round(tp / (tp + fp), 3) if tp + fp else None
    rec = round(tp / (tp + lost), 3) if tp + lost else None
    f1 = round(2 * prec * rec / (prec + rec), 3) if prec and rec else None
    executed = total - counts["MISS"]
    return {"conteggi": {c: counts[c] for c in CLASSES}, "precisione": prec, "richiamo": rec,
            "f1": f1, "accuratezza": round(ok / total, 3) if total else None,
            "copertura": round(executed / total, 3) if total else None,
            "inconcludenti": counts["INC"], "totale": total}


def evaluate(expected: dict[str, str], runs: list[dict[str, str | None]]) -> tuple[Counter, list[dict]]:
    """Confronta ogni ripetizione con l'atteso. Ritorna (conteggi, dettaglio per controllo)."""
    counts: Counter = Counter()
    detail = []
    for cid, exp in expected.items():
        found = [r.get(cid) for r in runs]
        classes = [classify(exp, f) for f in found]
        for c, f in zip(classes, found):
            counts[c] += 1
            if exp == "confirmed" and c in ("INC", "ERR", "MISS"):
                counts[f"{c}_POS"] += 1
        worst = next((c for c in WRONG + ("INC",) if c in classes), classes[-1] if classes else "")
        detail.append({"controllo": cid, "atteso": exp, "trovato": _tally(found),
                       "classe": _tally(classes), "classe_peggiore": worst,
                       "stabile": len(set(found)) <= 1})
    return counts, detail


def _tally(values) -> str:
    c = Counter(str(v) for v in values)
    if len(c) == 1:
        return next(iter(c))
    return ", ".join(f"{k} x{n}" for k, n in c.most_common())


# ================================================================== esecuzione

def run_v3(url: str):
    import Pentest_ollama_v2 as scanner
    scanner.PAUSA_TRA_RICHIESTE = 0
    scanner.trova_host_burp = lambda *a, **k: None
    t0 = time.time()
    r0 = scanner.STATISTICHE["richieste"]
    statuses = {}
    for controllo in scanner.CONTROLLI:
        f = controllo(url)
        if f["esito"] != "INFO":
            statuses[f["id"]] = V3_STATUS.get(f["esito"], "error")
    return statuses, {"secondi": round(time.time() - t0, 3),
                      "richieste": scanner.STATISTICHE["richieste"] - r0}


def run_v4(url: str, config: str, settings, model: str, store=None, ai_factory=None):
    from wpsec.core.authorization import AuthorizationRequest, create_authorization
    from wpsec.core.models import ScanOptions
    from wpsec.core.scan import AUTO, run_scan
    auth = create_authorization(AuthorizationRequest(
        kind="lab", target_url=url, authorizer_name="Laboratorio", authorizer_role="Tutor",
        operator="Benchmark", days=1, notes="Benchmark automatico"))
    use_ai = config in ("v4-ia", "v4-llm")
    options = ScanOptions(use_ai=use_ai, model=model,
                          planner="llm" if config == "v4-llm" else "deterministic",
                          label=f"bench {config}")
    ai = (ai_factory() if ai_factory else AUTO) if use_ai else None
    r = run_scan(url, auth, options, settings, ai=ai)
    if store is not None:
        store.save_scan(r)
    statuses = {f.check_id: f.status.value for f in r.findings}
    planner = r.stats.get("planner", {})
    info = {"secondi": r.duration_s, "richieste": r.stats.get("http", {}).get("requests", 0),
            "stato": r.status, "scan_id": r.id, "modello": r.model_used,
            "ia": r.stats.get("ai", {}), "pianificatore": planner,
            "note_ia": sum(len(f.ai_notes) for f in r.findings),
            "sintesi_ia": r.executive_summary_ai,
            "agenti_falliti": [a.name for a in r.agents if a.state.value == "failed"]}
    if use_ai and not r.model_used:
        info["avviso"] = "IA richiesta ma non disponibile: run eseguito senza IA"
    return statuses, info


def run_config(config: str, targets: list[dict], reps: int, mapping: dict, settings, model: str,
               store=None, ai_factory=None, log=print) -> dict:
    tot_full, tot_common = Counter(), Counter()
    per_target, infos = [], []
    for t in targets:
        runs_full, runs_common = [], []
        for i in range(reps):
            if config == "v3":
                st, info = run_v3(t["url"])
                common = {k: st.get(k) for k in mapping}
            else:
                st, info = run_v4(t["url"], config, settings, model, store, ai_factory)
                common = common_view(st, mapping)
                runs_full.append(st)
            runs_common.append(common)
            info["bersaglio"] = t["nome"]
            infos.append(info)
            log(f"  {config:7} {t['nome']:9} run {i + 1}/{reps}: {info['secondi']:.2f}s, "
                f"{info['richieste']} richieste" + (f" — {info['avviso']}" if info.get("avviso") else ""))
        exp_common = common_view(t["atteso"], mapping)
        c_common, d_common = evaluate(exp_common, runs_common)
        tot_common.update(c_common)
        entry = {"bersaglio": t["nome"], "comuni": d_common}
        if config != "v3":
            c_full, d_full = evaluate(t["atteso"], runs_full)
            tot_full.update(c_full)
            entry["completo"] = d_full
        per_target.append(entry)

    secs = [i["secondi"] for i in infos]
    reqs = [i["richieste"] for i in infos]
    eff = {"tempo_medio_s": round(statistics.mean(secs), 2),
           "tempo_dev_std_s": round(statistics.pstdev(secs), 2) if len(secs) > 1 else 0.0,
           "tempo_max_s": round(max(secs), 2), "richieste_medie": round(statistics.mean(reqs), 1),
           "run": len(infos)}
    if config in ("v4-ia", "v4-llm"):
        ai = Counter()
        for i in infos:
            ai.update({k: v for k, v in i.get("ia", {}).items() if isinstance(v, (int, float))})
        eff.update({"ia": dict(ai), "note_ia_medie": round(statistics.mean(i["note_ia"] for i in infos), 1),
                    "sintesi_ia": sum(1 for i in infos if i["sintesi_ia"]),
                    "run_senza_ia": sum(1 for i in infos if i.get("avviso"))})
    if config == "v4-llm":
        pl = [i["pianificatore"] for i in infos if i["pianificatore"]]
        eff.update({"decisioni_pianificatore": sum(p.get("decisions", 0) for p in pl),
                    "decisioni_non_valide": sum(p.get("invalid", 0) for p in pl),
                    "run_con_ripiego": sum(1 for p in pl if p.get("fallback"))})
    unstable = [(e["bersaglio"], d["controllo"], d["trovato"])
                for e in per_target for key in ("completo", "comuni") for d in e.get(key, [])
                if not d["stabile"]]
    return {"config": config, "ripetizioni": reps,
            "metriche_complete": metrics(tot_full) if config != "v3" else None,
            "metriche_comuni": metrics(tot_common), "efficienza": eff,
            "instabili": sorted(set(unstable)), "bersagli": per_target, "run": infos}


# ================================================================== rapporto

def _fmt(v):
    return "-" if v is None else str(v)


def to_markdown(res: dict) -> str:
    out = [f"# Benchmark v4 ({res['data']})", "",
           f"- Ground truth: versione {res['ground_truth']['versione']}, verificata il "
           f"{res['ground_truth']['verifica']['data']} ({res['ground_truth']['verifica']['wordpress']})",
           f"- Ripetizioni: {res['ripetizioni']} | modello IA: {res['modello']} | bersagli: "
           + ", ".join(res["bersagli"]), ""]
    out += ["## Controlli comuni v3/v4 (stessa ground truth)", "",
            "| Config | Precisione | Richiamo | F1 | Accuratezza | TP | TN | FP | FN | INC | ERR |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in res["risultati"]:
        m = r["metriche_comuni"]
        c = m["conteggi"]
        out.append(f"| {r['config']} | {_fmt(m['precisione'])} | {_fmt(m['richiamo'])} | {_fmt(m['f1'])} | "
                   f"{_fmt(m['accuratezza'])} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} | "
                   f"{c['INC']} | {c['ERR']} |")
    v4s = [r for r in res["risultati"] if r["metriche_complete"]]
    if v4s:
        out += ["", "## Tutti i controlli della v4", "",
                "| Config | Precisione | Richiamo | F1 | Accuratezza | Copertura | TP | TN | FP | FN | INC | NA | NA-X |",
                "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in v4s:
            m = r["metriche_complete"]
            c = m["conteggi"]
            out.append(f"| {r['config']} | {_fmt(m['precisione'])} | {_fmt(m['richiamo'])} | "
                       f"{_fmt(m['f1'])} | {_fmt(m['accuratezza'])} | {_fmt(m['copertura'])} | "
                       f"{c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} | {c['INC']} | {c['NA']} | {c['NA-X']} |")
    out += ["", "## Efficienza", "", "| Config | Tempo medio (s) | Dev. std | Max | Richieste medie | Altro |",
            "|---|---|---|---|---|---|"]
    for r in res["risultati"]:
        e = r["efficienza"]
        extra = {k: v for k, v in e.items() if k not in ("tempo_medio_s", "tempo_dev_std_s",
                                                         "tempo_max_s", "richieste_medie", "run")}
        out.append(f"| {r['config']} | {e['tempo_medio_s']} | {e['tempo_dev_std_s']} | {e['tempo_max_s']} | "
                   f"{e['richieste_medie']} | {json.dumps(extra, ensure_ascii=False) if extra else ''} |")
    for r in res["risultati"]:
        out += ["", f"## Dettaglio {r['config']}", ""]
        if r["instabili"]:
            out.append("Esiti instabili fra ripetizioni: " + "; ".join(
                f"{b}/{c}: {t}" for b, c, t in r["instabili"]))
            out.append("")
        key = "completo" if r["metriche_complete"] else "comuni"
        out += ["| Bersaglio | Controllo | Atteso | Trovato | Classe |", "|---|---|---|---|---|"]
        for e in r["bersagli"]:
            for d in e[key]:
                mark = " ⚠" if d["classe_peggiore"] in WRONG else ""
                out.append(f"| {e['bersaglio']} | {d['controllo']} | {d['atteso']} | {d['trovato']} | "
                           f"{d['classe']}{mark} |")
    return "\n".join(out) + "\n"


# ================================================================== main

def main(argv=None) -> int:
    from wpsec.config.settings import Settings
    ap = argparse.ArgumentParser(description="Benchmark v4 (e v3) contro la ground truth del laboratorio")
    ap.add_argument("-n", "--ripetizioni", type=int, default=3)
    ap.add_argument("--configs", default="v3,v4", help=f"elenco fra {', '.join(CONFIGS)} oppure 'all'")
    ap.add_argument("--modello", default="", help="modello Ollama (predefinito dalle impostazioni)")
    ap.add_argument("--verita", default=str(QUI / "ground_truth.json"))
    ap.add_argument("--solo", help="un solo bersaglio (es. wp-hard)")
    ap.add_argument("--out", default=str(QUI / "risultati_benchmark"))
    ap.add_argument("--db", help="archivio SQLite in cui salvare le scansioni v4 (facoltativo)")
    a = ap.parse_args(argv)

    configs = list(CONFIGS) if a.configs == "all" else [c.strip() for c in a.configs.split(",") if c.strip()]
    bad = [c for c in configs if c not in CONFIGS]
    if bad:
        ap.error(f"configurazioni sconosciute: {bad}")
    gt = json.loads(Path(a.verita).read_text(encoding="utf-8"))
    if gt.get("versione", 1) < 2:
        ap.error("serve la ground truth versione 2 (esiti v4)")
    targets = [t for t in gt["bersagli"] if not a.solo or t["nome"] == a.solo]
    if not targets:
        ap.error(f"bersaglio sconosciuto: {a.solo}")
    mapping = gt["corrispondenza_v3"]
    # laboratorio locale: nessuna pausa fra le richieste
    settings = Settings.from_env().with_overrides(min_interval=0.0)
    model = a.modello or settings.default_model
    store = None
    if a.db:
        from wpsec.database.store import Store
        store = Store(a.db)

    print(f"=== BENCHMARK v4: {', '.join(configs)} — {a.ripetizioni} ripetizioni ===")
    results = [run_config(c, targets, a.ripetizioni, mapping, settings, model, store) for c in configs]
    res = {"data": datetime.now().isoformat(timespec="seconds"), "ripetizioni": a.ripetizioni,
           "modello": model, "bersagli": [t["nome"] for t in targets],
           "ground_truth": {"versione": gt["versione"], "verifica": gt["verifica"]},
           "risultati": results}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    name = "benchmark_v4_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    (out / f"{name}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str),
                                      encoding="utf-8")
    md = to_markdown(res)
    (out / f"{name}.md").write_text(md, encoding="utf-8")
    print("\n" + md)
    print(f"[OK] Salvati in {out}/{name}.(json|md)")
    wrong = any(r["metriche_comuni"]["conteggi"][c] for r in results for c in WRONG if r["config"] != "v3")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
