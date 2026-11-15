#!/usr/bin/env python3
"""
Confronto prima/dopo tra due scansioni salvate in scansioni/.

Uso:
  python3 confronta.py                          # ultime due scansioni dello stesso sito (quello dell'ultima)
  python3 confronta.py --host esempio.it   # ultime due di quel sito
  python3 confronta.py prima.json dopo.json     # due file a scelta
  python3 confronta.py --anonimizza             # sostituisce gli username con utente1, utente2...
Il risultato è stampato e salvato come Markdown accanto agli snapshot.
"""

import argparse
import json
import re
import sys
from pathlib import Path

CARTELLA = Path(__file__).resolve().parent / "scansioni"


def carica(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def ultime_due(host=None):
    file = sorted(CARTELLA.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if host:
        file = [f for f in file if f.name.startswith(host + "_")]
    elif file:
        pref = file[-1].name.rsplit("_", 2)[0]
        file = [f for f in file if f.name.startswith(pref + "_")]
    if len(file) < 2:
        sys.exit("Servono almeno due scansioni dello stesso sito in scansioni/. "
                 "Lancia lo scanner prima e dopo le correzioni (usa --etichetta).")
    return file[-2], file[-1]


class Anonimizzatore:
    """Sostituisce gli username con nomi neutri, in modo coerente in tutto il documento."""

    def __init__(self, attivo):
        self.attivo, self.mappa = attivo, {}

    def _nome(self, valore):
        if valore not in self.mappa:
            self.mappa[valore] = f"utente{len(self.mappa) + 1}"
        return self.mappa[valore]

    def __call__(self, testo):
        if not self.attivo or not testo:
            return testo
        testo = re.sub(r"slug='([^']*)'", lambda m: f"slug='{self._nome(m.group(1))}'", testo)
        return re.sub(r"username '([^']*)'", lambda m: f"username '{self._nome(m.group(1))}'", testo)


def stato(prima, dopo):
    if "INFO" in (prima, dopo):
        return "INFO"
    if "ERRORE" in (prima, dopo) or prima is None or dopo is None:
        return "NON CONFRONTABILE"
    if prima == "VULNERABILE" and dopo == "PROTETTO":
        return "RISOLTO"
    if prima == "PROTETTO" and dopo == "VULNERABILE":
        return "NUOVO PROBLEMA"
    if prima == dopo == "VULNERABILE":
        return "ANCORA APERTO"
    return "INVARIATO"


def main():
    ap = argparse.ArgumentParser(description="Confronto prima/dopo tra scansioni")
    ap.add_argument("file", nargs="*", help="prima.json dopo.json (opzionali)")
    ap.add_argument("--host")
    ap.add_argument("--anonimizza", action="store_true")
    a = ap.parse_args()

    if len(a.file) == 2:
        fp, fd = Path(a.file[0]), Path(a.file[1])
    elif not a.file:
        fp, fd = ultime_due(a.host)
    else:
        sys.exit("Indica due file oppure nessuno.")
    p, d = carica(fp), carica(fd)
    anon = Anonimizzatore(a.anonimizza)

    rp = {r["id"]: r for r in p["risultati"]}
    rd = {r["id"]: r for r in d["risultati"]}
    ordine = list(rp) + [c for c in rd if c not in rp]
    righe, conteggi = [], {}
    for cid in ordine:
        x, y = rp.get(cid), rd.get(cid)
        s = stato(x and x["esito"], y and y["esito"])
        conteggi[s] = conteggi.get(s, 0) + 1
        titolo = (y or x)["titolo"]
        righe.append((titolo, x["esito"] if x else "-", y["esito"] if y else "-", s,
                      anon((y or x)["evidenza"])))

    out = [f"# Confronto prima/dopo: {d['bersaglio'] if not a.anonimizza else '(sito anonimizzato)'}", "",
           f"- Prima: {p['data']} {('(' + p['etichetta'] + ')') if p.get('etichetta') else ''}",
           f"- Dopo: {d['data']} {('(' + d['etichetta'] + ')') if d.get('etichetta') else ''}"]
    if p["bersaglio"] != d["bersaglio"]:
        out.append(f"- ATTENZIONE: bersagli diversi ({p['bersaglio']} / {d['bersaglio']})")
    out += ["", "| Controllo | Prima | Dopo | Stato |", "|---|---|---|---|"]
    out += [f"| {t} | {x} | {y} | **{s}** |" for t, x, y, s, _ in righe]
    out += ["", "## Evidenza nella scansione più recente", ""]
    out += [f"- {t}: {ev}" for t, _, _, _, ev in righe]
    risolti = conteggi.get("RISOLTO", 0)
    aperti = conteggi.get("ANCORA APERTO", 0)
    nuovi = conteggi.get("NUOVO PROBLEMA", 0)
    out += ["", f"**Sintesi:** {risolti} risolti, {aperti} ancora aperti, {nuovi} nuovi problemi."]
    if "INFO" in {s for _, _, _, s, _ in righe}:
        out.append("(I controlli INFO, come il rilevamento WAF, sono solo contesto e non sono conteggiati.)")
    testo = "\n".join(out) + "\n"
    print(testo)
    dest = fd.with_name(f"confronto_{fd.stem}.md")
    dest.write_text(testo, encoding="utf-8")
    print(f"[OK] Salvato in {dest}")


if __name__ == "__main__":
    main()
