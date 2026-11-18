"""Benchmark v4: classificazione, aggregazione, metriche e un'esecuzione sui siti simulati."""

import json
from collections import Counter

import pytest

import benchmark_v4 as bm  # lab/benchmark_v4.py
from tests.helpers import FAST

MAPPING = {"utenti": "wp.users_rest", "header": ["http.header.csp", "http.header.hsts"]}


@pytest.mark.parametrize("exp,found,cls", [
    ("confirmed", "confirmed", "TP"), ("confirmed", "not_present", "FN"),
    ("confirmed", "false_positive", "FN"), ("confirmed", "inconclusive", "INC"),
    ("confirmed", "error", "ERR"), ("confirmed", None, "MISS"),
    ("not_present", "not_present", "TN"), ("not_present", "false_positive", "TN"),
    ("not_present", "confirmed", "FP"), ("not_present", "inconclusive", "INC"),
    ("not_applicable", "not_applicable", "NA"), ("not_applicable", "confirmed", "NA-X"),
])
def test_classificazione(exp, found, cls):
    assert bm.classify(exp, found) == cls


def test_aggregazione_header():
    assert bm.aggregate(["not_present", "confirmed", "not_applicable"]) == "confirmed"
    assert bm.aggregate(["not_present", "inconclusive"]) == "inconclusive"
    assert bm.aggregate(["not_present", "not_applicable"]) == "not_present"
    assert bm.aggregate(["not_applicable"]) == "not_applicable"
    assert bm.aggregate([None]) is None


def test_vista_sui_controlli_comuni():
    v = bm.common_view({"wp.users_rest": "confirmed", "http.header.csp": "not_present",
                        "http.header.hsts": "not_applicable"}, MAPPING)
    assert v == {"utenti": "confirmed", "header": "not_present"}


def test_inconcludente_su_un_positivo_abbassa_il_richiamo():
    c, detail = bm.evaluate({"a": "confirmed", "b": "not_present"},
                            [{"a": "confirmed", "b": "not_present"}, {"a": "inconclusive", "b": "not_present"}])
    m = bm.metrics(c)
    assert m["precisione"] == 1.0 and m["richiamo"] == 0.5 and m["inconcludenti"] == 1
    a = next(d for d in detail if d["controllo"] == "a")
    assert a["stabile"] is False and a["classe_peggiore"] == "INC"


def test_metriche_con_falso_positivo_e_non_eseguito():
    c = Counter({"TP": 3, "FP": 1, "MISS": 1, "MISS_POS": 1, "TN": 5})
    m = bm.metrics(c)
    assert m["precisione"] == 0.75 and m["richiamo"] == 0.75 and m["copertura"] == 0.9


def test_benchmark_v4_sui_siti_simulati(mock_sites, tmp_path):
    """Esecuzione completa della configurazione v4 con una ground truth dei simulatori."""
    from wpsec.database.store import Store
    targets = [{"nome": "wp-tricky", "url": mock_sites["wp-tricky"], "atteso": {
        "wp.users_rest": "confirmed",          # in realtà ignoto: il WAF blocca -> INC atteso
        "wp.version_disclosure": "confirmed",
        "wp.directory_listing": "not_present",
        "http.header.hsts": "not_applicable"}}]
    store = Store(tmp_path / "b.sqlite3")
    res = bm.run_config("v4", targets, 2, {"utenti": "wp.users_rest"}, FAST, "", store,
                        log=lambda *a: None)
    m = res["metriche_complete"]
    assert m["conteggi"]["INC"] == 2 and m["conteggi"]["FP"] == 0
    assert m["conteggi"]["TN"] == 2  # falso positivo della v3 scartato dalla v4
    assert res["efficienza"]["run"] == 2 and not res["instabili"]
    assert len(store.list_scans()) == 2
    md = bm.to_markdown({"data": "x", "ripetizioni": 2, "modello": "-", "bersagli": ["wp-tricky"],
                         "ground_truth": {"versione": 2, "verifica": {"data": "x", "wordpress": "y"}},
                         "risultati": [res]})
    assert "| v4 |" in md and "wp-tricky" in md


def test_ground_truth_del_laboratorio_coerente():
    from pathlib import Path
    from wpsec.knowledge.catalog import CATALOG
    gt = json.loads((Path(bm.QUI) / "ground_truth.json").read_text(encoding="utf-8"))
    assert gt["versione"] == 2 and gt["modifiche"]
    for t in gt["bersagli"]:
        assert set(t["atteso_v3"]) == set(gt["corrispondenza_v3"])
        for cid, st in t["atteso"].items():
            assert cid in CATALOG and st in ("confirmed", "not_present", "not_applicable")
    ids = [i for v in gt["corrispondenza_v3"].values() for i in (v if isinstance(v, list) else [v])]
    assert all(i in CATALOG for i in ids)
