import csv
import shutil
from datetime import UTC, datetime
from pathlib import Path

from dfir_triage.schema import CSV_COLUMNS, TimelineEvent, sort_key
from dfir_triage.timeline import build_timeline, classify, write_csv


def _event(ts):
    return TimelineEvent(ts, "EventRecorded", "evtx", "Security", "x", "a.evtx")


def test_classify_is_case_insensitive():
    assert classify(Path("x/Security.EVTX")) == "evtx"
    assert classify(Path("x/NTUSER.DAT")) == "ntuser_hive"
    assert classify(Path("x/ntuser.dat")) == "ntuser_hive"
    assert classify(Path("x/SYSTEM")) == "system_hive"
    assert classify(Path("x/Amcache.hve")) == "amcache_hive"
    assert classify(Path("x/notes.txt")) is None


def test_sort_puts_missing_timestamps_last():
    a = _event(datetime(2026, 1, 2, tzinfo=UTC))
    b = _event(None)
    c = _event(datetime(2026, 1, 1, tzinfo=UTC))
    assert sorted([a, b, c], key=sort_key) == [c, a, b]


def test_build_timeline_merges_and_sorts(sample_data):
    events, results = build_timeline(sample_data)
    assert len(results) == 3
    assert all(r.error is None for r in results)
    assert sum(r.events for r in results) == len(events) == 12
    times = [e.timestamp for e in events]
    assert times == sorted(times)


def test_bad_file_is_reported_not_fatal(tmp_path, sample_data):
    shutil.copy(sample_data / "Execution_exec_driveby_cve-2018-15982_sysmon_1_10.evtx", tmp_path)
    (tmp_path / "SYSTEM").write_bytes(b"this is not a registry hive")

    events, results = build_timeline(tmp_path)
    by_kind = {r.kind: r for r in results}
    assert by_kind["evtx"].events == 2
    assert by_kind["system_hive"].error is not None
    assert len(events) == 2


def test_write_csv_has_expected_columns(tmp_path, sample_data):
    events, _ = build_timeline(sample_data)
    out = tmp_path / "timeline.csv"
    write_csv(events, out)
    with open(out, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert len(rows) == len(events)
    assert rows[0]["timestamp"].endswith("Z")
