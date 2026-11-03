import io
import json
import urllib.error

from dfir_triage import summarizer
from dfir_triage.rules import run_rules
from dfir_triage.timeline import build_timeline, to_dataframe


def _sample(sample_data):
    events, _ = build_timeline(sample_data)
    return to_dataframe(events), run_rules(events)


def test_prompt_includes_findings_and_timeline(sample_data):
    df, findings = _sample(sample_data)
    prompt = summarizer.build_user_prompt(df, findings)
    assert "HIGH DT-001 Event log cleared [T1070.001]" in prompt
    assert "Timeline (12 total events)" in prompt
    assert "EID 4624" in prompt


def test_system_prompt_treats_evidence_as_untrusted():
    assert "UNTRUSTED DATA" in summarizer.SYSTEM_PROMPT


def test_rejects_unknown_provider_and_empty_timeline(sample_data):
    df, _ = _sample(sample_data)
    assert summarizer.summarize_timeline(df, provider="nope").startswith("ERROR:")
    assert summarizer.summarize_timeline(df.head(0)).startswith("ERROR:")


def test_ollama_request_and_response(sample_data, monkeypatch):
    df, findings = _sample(sample_data)
    sent = {}

    def fake_urlopen(request, timeout):
        sent["url"] = request.full_url
        sent["body"] = json.loads(request.data)
        return io.BytesIO(json.dumps({"message": {"content": "report text"}}).encode())

    monkeypatch.setenv("OLLAMA_MODEL", "test-model")
    monkeypatch.setattr(summarizer.urllib.request, "urlopen", fake_urlopen)

    assert summarizer.summarize_timeline(df, findings, provider="ollama") == "report text"
    assert sent["url"] == "http://localhost:11434/api/chat"
    assert sent["body"]["model"] == "test-model"
    assert sent["body"]["stream"] is False
    assert sent["body"]["messages"][0]["content"] == summarizer.SYSTEM_PROMPT


def test_ollama_unreachable_returns_error(sample_data, monkeypatch):
    df, _ = _sample(sample_data)

    def refuse(request, timeout):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(summarizer.urllib.request, "urlopen", refuse)
    result = summarizer.summarize_timeline(df, provider="ollama")
    assert result.startswith("ERROR: could not reach Ollama")


def test_retired_model_errors_are_recognised():
    assert summarizer._is_decommissioned_error(Exception("model_decommissioned"))
    retired = "Error code: 404 - The model llama-3.3-70b-versatile does not exist (model_not_found)"
    assert summarizer._is_decommissioned_error(Exception(retired))
    assert not summarizer._is_decommissioned_error(Exception("rate limit exceeded"))
