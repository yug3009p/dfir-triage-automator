from datetime import UTC, datetime

import pytest
from fakes import FakeKey, select_key, shimcache_blob, tree

from dfir_triage.parsers.shimcache import (
    UnsupportedShimcacheFormat,
    parse_appcompatcache,
    parse_shimcache,
)
from dfir_triage.schema import TIME_FILE_MODIFIED

T1 = datetime(2026, 2, 1, 8, 30, tzinfo=UTC)
T2 = datetime(2025, 12, 24, 23, 59, 59, tzinfo=UTC)


@pytest.mark.parametrize("header_size", [0x30, 0x34])
def test_parses_windows10_entries_in_order(header_size):
    blob = shimcache_blob(
        [("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", T1), ("C:\\Windows\\notepad.exe", T2)],
        header_size,
    )
    entries = parse_appcompatcache(blob)
    assert [e.position for e in entries] == [0, 1]
    assert entries[0].path == "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"
    assert entries[0].last_modified == T1
    assert entries[1].last_modified == T2


def test_zero_filetime_becomes_none():
    entries = parse_appcompatcache(shimcache_blob([("C:\\a.exe", None)]))
    assert entries[0].last_modified is None


def test_rejects_non_windows10_header():
    with pytest.raises(UnsupportedShimcacheFormat):
        parse_appcompatcache(b"\x80\x00\x00\x00" + b"\x00" * 200)


def test_parse_shimcache_uses_current_control_set():
    blob = shimcache_blob([("C:\\evil.exe", T1)])
    appcompat = FakeKey("AppCompatCache", values={"AppCompatCache": blob})
    root = tree(
        "ControlSet002\\Control\\Session Manager\\AppCompatCache",
        appcompat,
        extra_root_subkeys=[select_key(current=2)],
    )
    events = parse_shimcache(root, "SYSTEM", host="WS01")
    assert len(events) == 1
    assert events[0].path == "C:\\evil.exe"
    assert events[0].time_meaning == TIME_FILE_MODIFIED
    assert events[0].host == "WS01"


def test_parse_shimcache_missing_key_returns_empty():
    root = FakeKey("ROOT", subkeys=[select_key()])
    assert parse_shimcache(root, "SYSTEM") == []
