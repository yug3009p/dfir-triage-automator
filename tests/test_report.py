from datetime import UTC, datetime

from dfir_triage.report import attack_url, render_report
from dfir_triage.rules import run_rules
from dfir_triage.schema import TimelineEvent
from dfir_triage.timeline import ArtifactResult, build_timeline

PAYLOAD = '<script>alert("pwned")</script>'


def test_attack_url_handles_subtechniques():
    assert attack_url("T1070.001") == "https://attack.mitre.org/techniques/T1070/001/"
    assert attack_url("T1098") == "https://attack.mitre.org/techniques/T1098/"


def test_report_shows_findings_and_coverage(sample_data):
    events, artifacts = build_timeline(sample_data)
    html = render_report(events, run_rules(events), artifacts, "sample_data")
    assert "DT-001" in html and "DT-002" in html
    assert "T1550/002" in html  # ATT&CK link
    assert html.count("parsed</span>") == 3
    assert "LLM summary" not in html  # only shown when a summary is given


def test_report_escapes_attacker_controlled_fields():
    # A log field is attacker-controlled; it must render as text, not as markup.
    event = TimelineEvent(
        datetime(2026, 1, 1, tzinfo=UTC),
        "EventRecorded",
        "evtx",
        "Security",
        PAYLOAD,
        PAYLOAD,
        1102,
        host=PAYLOAD,
        user=PAYLOAD,
        path=PAYLOAD,
    )
    html = render_report(
        [event], run_rules([event]), [ArtifactResult(PAYLOAD, "evtx", 1)], PAYLOAD, PAYLOAD
    )
    assert PAYLOAD not in html
    assert "&lt;script&gt;" in html


def test_report_truncates_timeline_but_reports_total(sample_data):
    events, artifacts = build_timeline(sample_data)
    html = render_report(events, [], artifacts, "x", max_timeline_rows=5)
    assert "Showing the first 5 of 12 events" in html
    assert "No rule matched" in html


def test_report_marks_failed_artifacts():
    html = render_report([], [], [ArtifactResult("SYSTEM", "system_hive", error="bad hive")], "x")
    assert "bad hive" in html
    assert "(1 failed)" in html
