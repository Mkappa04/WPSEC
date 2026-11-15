"""Caratterizzazione dello scanner v3 (Pentest_ollama_v2.py).

Fissa gli esiti del codice ORIGINALE sui siti simulati. Questi valori sono il
riferimento per i test di parità della piattaforma v4 (test_parity.py).
Su wp-tricky documentano gli errori noti della v3 (falso positivo e falsi negativi).
"""

import pytest

import Pentest_ollama_v2 as legacy

pytestmark = pytest.mark.legacy

ATTESI_V3 = {
    "wp-vuln": dict(utenti="VULNERABILE", author="VULNERABILE", xmlrpc="VULNERABILE",
                    header="VULNERABILE", versione="VULNERABILE", uploads="VULNERABILE", waf="INFO"),
    "wp-hard": dict(utenti="PROTETTO", author="PROTETTO", xmlrpc="PROTETTO",
                    header="PROTETTO", versione="PROTETTO", uploads="PROTETTO", waf="INFO"),
    "wp-mixed": dict(utenti="VULNERABILE", author="VULNERABILE", xmlrpc="PROTETTO",
                     header="VULNERABILE", versione="PROTETTO", uploads="VULNERABILE", waf="INFO"),
    # Errori noti della v3 su wp-tricky:
    #  - utenti: il 403 del WAF viene letto come PROTETTO (in realtà non verificabile)
    #  - versione: esposta nel feed, ma la v3 guarda solo il meta generator -> PROTETTO
    #  - uploads: la parola "Index of" in un articolo -> VULNERABILE (falso positivo)
    "wp-tricky": dict(utenti="PROTETTO", author="PROTETTO", xmlrpc="PROTETTO",
                      header="PROTETTO", versione="PROTETTO", uploads="VULNERABILE", waf="INFO"),
}


@pytest.fixture(autouse=True)
def _senza_burp_e_pause(monkeypatch):
    monkeypatch.setattr(legacy, "PAUSA_TRA_RICHIESTE", 0)
    monkeypatch.setattr(legacy, "trova_host_burp", lambda *a, **k: None)


def esegui_v3(url):
    return {f["id"]: f for f in (c(url) for c in legacy.CONTROLLI)}


@pytest.mark.parametrize("sito", list(ATTESI_V3))
def test_esiti_v3(mock_sites, sito):
    ris = esegui_v3(mock_sites[sito])
    assert {k: v["esito"] for k, v in ris.items()} == ATTESI_V3[sito]


def test_waf_rilevato_v3(mock_sites):
    ris = esegui_v3(mock_sites["wp-waf"])
    assert "BitNinja" in ris["waf"]["evidenza"]


def test_v3_scarica_la_home_tre_volte(mock_sites):
    """Documenta l'inefficienza C7: header, versione e WAF rifanno GET /."""
    prima = legacy.STATISTICHE["richieste"]
    esegui_v3(mock_sites["wp-hard"])
    # 7 controlli: utenti(2) author(1) xmlrpc(1) header(1) versione(1) uploads(1) waf(1) = 8
    assert legacy.STATISTICHE["richieste"] - prima == 8
