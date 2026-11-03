import csv

from dfir_triage import cli


def test_cli_writes_all_outputs(sample_data, tmp_path, capsys):
    assert cli.main([str(sample_data), "-o", str(tmp_path)]) == 0

    assert (tmp_path / "report.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    with open(tmp_path / "timeline.csv", encoding="utf-8") as fh:
        assert len(list(csv.DictReader(fh))) == 12
    with open(tmp_path / "findings.csv", encoding="utf-8") as fh:
        findings = list(csv.DictReader(fh))
    assert [row["rule_id"] for row in findings] == ["DT-001", "DT-002"]
    assert findings[0]["technique_id"] == "T1070.001"

    out = capsys.readouterr().out
    assert "Parsed 3/3 artifacts, 12 events" in out
    assert "HIGH   2 finding(s)" in out


def test_cli_missing_folder_returns_2(tmp_path, capsys):
    assert cli.main([str(tmp_path / "nope")]) == 2
    assert "not found" in capsys.readouterr().err


def test_cli_empty_folder_returns_2(tmp_path, capsys):
    assert cli.main([str(tmp_path), "-o", str(tmp_path / "out")]) == 2
    assert "no .evtx files" in capsys.readouterr().err


def test_cli_summary_failure_still_writes_report(sample_data, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "summarize_timeline", lambda *a, **k: "ERROR: provider down")
    assert cli.main([str(sample_data), "-o", str(tmp_path), "--summarize", "ollama"]) == 0
    assert (tmp_path / "report.html").exists()
    assert "ERROR: provider down" in capsys.readouterr().err


def test_cli_embeds_summary_when_available(sample_data, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "summarize_timeline", lambda *a, **k: "## 1. Executive Summary\nok")
    assert cli.main([str(sample_data), "-o", str(tmp_path), "--summarize", "groq"]) == 0
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "LLM summary (advisory)" in html
    assert "Executive Summary" in html
