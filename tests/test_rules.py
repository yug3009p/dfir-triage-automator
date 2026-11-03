import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage.rules import RULES, run_rules
from dfir_triage.schema import TimelineEvent
from dfir_triage.timeline import build_timeline

T0 = datetime(2026, 1, 1, tzinfo=UTC)
README = Path(__file__).resolve().parent.parent / "README.md"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def evtx(event_id, channel="Security", path=None, **details):
    return TimelineEvent(
        T0, "EventRecorded", "evtx", channel, "x", "a.evtx", event_id, path=path, details=details
    )


def artifact(source, path=None, event_type="", **details):
    return TimelineEvent(
        T0, "KeyLastWrite", source, event_type, "x", "hive", path=path, details=details
    )


def rule_ids(event):
    return {f.rule.id for f in run_rules([event])}


# Each case: (rule id, event that must fire, similar event that must NOT fire)
CASES = [
    ("DT-001", evtx(1102), evtx(1100)),
    ("DT-001", evtx(104, "System"), evtx(104, "Application")),
    (
        "DT-002",
        evtx(4624, LogonType="9", LogonProcessName="seclogo"),
        evtx(4624, LogonType="2", LogonProcessName="User32"),
    ),
    (
        "DT-003",
        evtx(10, SYSMON, TargetImage="C:\\Windows\\system32\\lsass.exe"),
        evtx(10, SYSMON, TargetImage="C:\\Windows\\system32\\cmd.exe"),
    ),
    (
        "DT-004",
        evtx(4688, CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi"),
        evtx(4688, CommandLine="powershell.exe -ExecutionPolicy Bypass -File update.ps1"),
    ),
    (
        "DT-004",
        evtx(1, SYSMON, CommandLine="pwsh -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBi"),
        evtx(
            1, "Security", CommandLine="pwsh -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBi"
        ),  # ID 1 is not 4688
    ),
    (
        "DT-005",
        evtx(7045, "System", ImagePath="cmd.exe /c C:\\Windows\\Temp\\p.exe"),
        evtx(7045, "System", ImagePath="C:\\Program Files\\Vendor\\svc.exe"),
    ),
    (
        "DT-005",
        artifact("registry", event_type="service", image_path="C:\\Users\\Public\\svc.exe"),
        artifact(
            "registry", event_type="service", image_path="C:\\Windows\\System32\\svchost.exe -k"
        ),
    ),
    ("DT-006", evtx(7045, "System", ImagePath="x"), evtx(7036, "System")),
    ("DT-006", evtx(4697), evtx(4697, SYSMON)),
    ("DT-007", evtx(4698), evtx(4699)),
    ("DT-008", evtx(4720), evtx(4726)),
    ("DT-009", evtx(4732), evtx(4733)),
    (
        "DT-010",
        evtx(1, SYSMON, path="C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe"),
        evtx(1, SYSMON, path="C:\\Windows\\System32\\notepad.exe"),
    ),
    (
        "DT-010",
        artifact("shimcache", path="C:\\Users\\bob\\Downloads\\setup.exe"),
        artifact("registry", path="C:\\Users\\bob\\Downloads\\setup.exe", event_type="run_key"),
    ),
    (
        "DT-011",
        artifact("registry", event_type="run_key"),
        artifact("registry", event_type="service"),
    ),
]


@pytest.mark.parametrize("rule_id,positive,negative", CASES)
def test_rule_fires_on_positive_only(rule_id, positive, negative):
    assert rule_id in rule_ids(positive)
    assert rule_id not in rule_ids(negative)


def test_every_rule_has_a_test_case():
    assert {r.id for r in RULES} == {case[0] for case in CASES}


def test_rule_metadata_is_well_formed():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for rule in RULES:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", rule.technique_id), rule.id
        assert rule.severity in ("high", "medium", "low")
        assert rule.note


def test_every_rule_is_documented_in_readme():
    readme = README.read_text(encoding="utf-8")
    for rule in RULES:
        assert rule.id in readme, f"{rule.id} missing from README rule table"


def test_findings_sorted_by_severity_then_time():
    later = TimelineEvent(
        datetime(2026, 1, 2, tzinfo=UTC), "EventRecorded", "evtx", "Security", "x", "a", 1102
    )
    findings = run_rules([artifact("registry", event_type="run_key"), later, evtx(1102)])
    assert [f.rule.severity for f in findings] == ["high", "high", "low"]
    assert findings[0].event.timestamp < findings[1].event.timestamp


def test_samples_produce_expected_findings(sample_data):
    events, _ = build_timeline(sample_data)
    found = sorted((f.rule.id, f.event.event_id) for f in run_rules(events))
    # Lateral-movement sample: audit log cleared, then a pass-the-hash logon.
    assert found == [("DT-001", 1102), ("DT-002", 4624)]
