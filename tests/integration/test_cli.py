"""CLI main.py sui siti simulati (database in una cartella temporanea)."""

import json
from pathlib import Path

import pytest

import main

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSEC_MIN_INTERVAL", "0")

    def _run(*args):
        return main.main(["--data-dir", str(tmp_path), *args])
    _run.dir = tmp_path
    return _run


def test_scan_lab_report_e_confronto(run, mock_sites, capsys):
    url = mock_sites["wp-vuln"]
    assert run("scan", "--lab", url, "--no-ai", "--label", "prima", "--formats", "html,md") == 0
    assert run("scan", "--lab", url, "--no-ai", "--label", "dopo", "--formats", "") == 0
    out = capsys.readouterr().out
    assert "[completed] Evidence Validation Agent" in out
    assert len(list((run.dir / "reports").glob("*.html"))) == 1
    # la seconda scansione riusa la stessa autorizzazione di laboratorio
    run("auth", "list")
    assert capsys.readouterr().out.count("lab") == 1
    run("list")
    rows = capsys.readouterr().out.strip().splitlines()
    assert len(rows) == 2
    scan_id = rows[0].split()[0]
    assert run("report", scan_id, "--formats", "pdf", "--anonymize") == 0
    assert (run.dir / "reports" / f"{scan_id}-anon.pdf").exists()
    assert run("compare", "--host", "127.0.0.1", "--save") == 0
    out = capsys.readouterr().out
    assert "0 risolti" in out and list((run.dir / "reports").glob("confronto_*.md"))
    assert run("timeline", "127.0.0.1") == 0
    assert "confermato 2/2" in capsys.readouterr().out


def test_auth_add_sito_reale_con_documento(run, tmp_path, capsys):
    doc = tmp_path / "lettera.pdf"
    doc.write_bytes(b"autorizzazione firmata")
    assert run("auth", "add", "--target", "https://www.sito.it", "--by", "Mario Rossi",
               "--role", "Titolare", "--operator", "Studente", "--doc", "Lettera 10/11",
               "--doc-file", str(doc), "--days", "7") == 0
    assert "sha256" in capsys.readouterr().out


def test_errori_restituiscono_codice_2(run, mock_sites, capsys):
    assert run("auth", "add", "--target", "https://www.sito.it", "--by", "Mario Rossi",
               "--role", "Titolare", "--operator", "Studente") == 2
    assert "documento" in capsys.readouterr().err
    assert run("scan", "--auth", "auth-nessuna", "--target", mock_sites["wp-vuln"]) == 2
    assert run("compare", "--host", "127.0.0.1") == 2


def test_import_v3(run, capsys, tmp_path):
    files = sorted(str(p) for p in (ROOT / "scansioni").glob("*.json"))
    if not files:
        pytest.skip("nessuna scansione v3")
    escluso = tmp_path / "aternos.org_20261113_123448.json"  # sintetico: host sempre escluso
    escluso.write_text(json.dumps({
        "scanner": "3.0", "data": "2026-11-13T12:34:48", "bersaglio": "https://aternos.org",
        "risultati": [{"id": "xmlrpc", "titolo": "XML-RPC", "esito": "PROTETTO",
                       "gravita": "Media", "evidenza": "HTTP 403"}]}))
    code = run("import-v3", *files, str(escluso))
    out = capsys.readouterr().out
    assert "rifiutato" in out and "aternos.org" in out  # mai importato
    assert code == 2  # almeno un file rifiutato
    run("list")
    assert "legacy-v3" in capsys.readouterr().out


def test_serve_rifiuta_host_remoto(run):
    with pytest.raises(SystemExit, match="allow-remote"):
        run("serve", "--host", "0.0.0.0")
