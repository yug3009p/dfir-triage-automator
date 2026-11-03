"""Tests for lab/compare.py using hand-built ground truth and timeline events."""

import csv
import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path

from dfir_triage.schema import TimelineEvent
from dfir_triage.timeline import ArtifactResult

spec = importlib.util.spec_from_file_location(
    "compare", Path(__file__).resolve().parent.parent / "lab" / "compare.py"
)
compare = importlib.util.module_from_spec(spec)
sys.modules["compare"] = compare  # @dataclass looks its module up in sys.modules
spec.loader.exec_module(compare)

STAGE = "C:\\Users\\Public\\stage.exe"
SETUP = "C:\\Users\\lab\\Downloads\\setup.exe"
SHA1 = "a" * 40
MODIFIED = "2026-05-06T07:08:09.1234567Z"  # PowerShell's 7-digit fractions
MODIFIED_DT = datetime(2026, 5, 6, 7, 8, 9, 123456, tzinfo=UTC)

TRUTH = {
    "hostname": "LABWS01",
    "started_utc": "2026-11-03T20:00:00Z",
    "steps": [
        {
            "name": "run_from_public",
            "expected_rules": ["DT-010"],
            "data": {
                "stage": {"path": STAGE, "sha1": SHA1, "last_write_utc": MODIFIED},
                "setup": {"path": SETUP, "sha1": "b" * 40, "last_write_utc": MODIFIED},
            },
        },
        {
            "name": "run_key",
            "expected_rules": ["DT-011"],
            "data": {"value_name": "LabUpdater", "command": STAGE},
        },
        {
            "name": "service",
            "expected_rules": ["DT-005", "DT-006"],
            "data": {"service": "LabSvc", "image_path": "cmd.exe /c echo lab"},
        },
    ],
}


def ev(source, event_type, path=None, ts=None, **details):
    return TimelineEvent(ts, "x", source, event_type, "x", "a", path=path, details=details)


def good_events():
    return [
        ev("shimcache", "shimcache_entry", STAGE, MODIFIED_DT, cache_position="3"),
        ev("amcache", "amcache_file", STAGE.lower(), None, sha1=SHA1),
        ev("registry", "run_key", STAGE, None, value_name="LabUpdater", command=STAGE),
        ev(
            "registry",
            "service",
            "cmd.exe /c echo lab",
            None,
            service="LabSvc",
            image_path="cmd.exe /c echo lab",
        ),
        ev("userassist", "userassist", SETUP, None, run_count="1"),
    ]


def statuses(checks):
    return {c.name: c.status for c in checks}


def test_parse_utc_handles_powershell_and_ez_formats():
    assert compare.parse_utc(MODIFIED) == MODIFIED_DT
    assert compare.parse_utc("2026-05-06 07:08:09") == datetime(2026, 5, 6, 7, 8, 9, tzinfo=UTC)
    assert compare.parse_utc("") is None


def test_correct_parsers_pass():
    result = statuses(compare.check_parsers(TRUTH, good_events()))
    assert result["shimcache: timestamp = file last-modified time"] == "PASS"
    assert result["amcache: stage.exe SHA-1 = real file SHA-1"] == "PASS"
    assert result["amcache: setup.exe present"] == "WARN"  # not inventoried: warning only
    assert result["registry: Run key LabUpdater"] == "PASS"
    assert result["registry: service LabSvc"] == "PASS"
    assert result["userassist: setup.exe launch"] == "PASS"


def test_wrong_values_fail():
    events = good_events()
    events[0] = ev("shimcache", "shimcache_entry", STAGE, datetime(2020, 1, 1, tzinfo=UTC))
    events[1] = ev("amcache", "amcache_file", STAGE, None, sha1="c" * 40)
    events[3] = ev("registry", "service", None, None, service="LabSvc", image_path="C:\\other.exe")
    result = statuses(compare.check_parsers(TRUTH, events))
    assert result["shimcache: timestamp = file last-modified time"] == "FAIL"
    assert result["amcache: stage.exe SHA-1 = real file SHA-1"] == "FAIL"
    assert result["registry: service LabSvc"] == "FAIL"


def test_missing_shimcache_entry_fails():
    result = statuses(compare.check_parsers(TRUTH, good_events()[1:]))
    assert result["shimcache: stage.exe present"] == "FAIL"


def test_rule_and_coverage_checks():
    class FakeRule:
        def __init__(self, rid):
            self.id = rid

    class FakeFinding:
        def __init__(self, rid):
            self.rule = FakeRule(rid)

    rules = statuses(compare.check_rules(TRUTH, [FakeFinding("DT-005"), FakeFinding("DT-010")]))
    assert rules == {
        "rule fired: DT-005": "PASS",
        "rule fired: DT-006": "FAIL",
        "rule fired: DT-010": "PASS",
        "rule fired: DT-011": "FAIL",
    }

    cov = statuses(
        compare.check_coverage(
            [
                ArtifactResult("SYSTEM", "system_hive", 5),
                ArtifactResult("x.evtx", "evtx", error="bad"),
            ]
        )
    )
    assert cov["artifact parsed: system_hive"] == "PASS"
    assert cov["artifact parsed: evtx"] == "FAIL"
    assert cov["artifact parsed: amcache_hive"] == "FAIL"


def test_ez_comparison(tmp_path):
    with open(tmp_path / "shimcache.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC"])
        w.writerow(["1", "3", STAGE, "2026-05-06 07:08:09"])
    with open(
        tmp_path / "20261103_Amcache_UnassociatedFileEntries.csv", "w", newline="", encoding="utf-8"
    ) as fh:
        w = csv.writer(fh)
        w.writerow(["FullPath", "SHA1"])
        w.writerow([STAGE.lower(), SHA1])
    result = statuses(compare.check_against_ez(good_events(), tmp_path))
    assert result == {
        "EZ shimcache: same entries": "PASS",
        "EZ shimcache: same timestamps": "PASS",
        "EZ amcache: same SHA-1 set": "PASS",
    }
