from datetime import UTC, datetime

from fakes import FakeKey, tree

from dfir_triage.parsers.amcache import parse_amcache, sha1_from_file_id
from dfir_triage.schema import TIME_KEY_LAST_WRITE

SHA1 = "a" * 40


def test_sha1_strips_four_zero_prefix():
    assert sha1_from_file_id("0000" + SHA1.upper()) == SHA1
    assert sha1_from_file_id(None) is None


def test_parse_amcache_inventory_entries():
    entry = FakeKey(
        "0006abc",
        values={
            "LowerCaseLongPath": "c:\\users\\bob\\downloads\\tool.exe",
            "FileId": "0000" + SHA1,
            "Name": "tool.exe",
            "Publisher": "",
            "Size": 12345,
        },
        timestamp=datetime(2026, 3, 1, 10, 0, 0),
    )
    root = tree(
        "Root\\InventoryApplicationFile", FakeKey("InventoryApplicationFile", subkeys=[entry])
    )

    [event] = parse_amcache(root, "Amcache.hve")
    assert event.path == "c:\\users\\bob\\downloads\\tool.exe"
    assert event.details["sha1"] == SHA1
    assert event.details["size"] == "12345"
    assert "publisher" not in event.details  # empty values are dropped
    assert event.timestamp == datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC)
    assert event.time_meaning == TIME_KEY_LAST_WRITE


def test_parse_amcache_old_format_returns_empty():
    assert parse_amcache(FakeKey("ROOT", subkeys=[FakeKey("Root")]), "Amcache.hve") == []


def test_parse_amcache_minimal_entries_use_key_name():
    # Windows 11 26H2 (build 26300) lab hive: entries hold only ProgramId and FileId,
    # and the subkey name carries the file name cut at 16 characters.
    entry = FakeKey(
        "aggregatorhost.e|2f15385328865347",
        values={"ProgramId": "0000f519", "FileId": "0000" + SHA1},
        timestamp=datetime(2026, 11, 4, 5, 27, 6),
    )
    root = tree(
        "Root\\InventoryApplicationFile", FakeKey("InventoryApplicationFile", subkeys=[entry])
    )

    [event] = parse_amcache(root, "Amcache.hve")
    assert event.path is None
    assert event.details["sha1"] == SHA1
    assert event.details["name_from_key"] == "aggregatorhost.e"
    assert "no path recorded" in event.description
