import codecs
from datetime import UTC, datetime

from fakes import FakeKey, select_key, tree, userassist_data

from dfir_triage.parsers.registry import (
    NTUSER_RUN_KEYS,
    decode_userassist_name,
    parse_run_keys,
    parse_services,
    parse_userassist,
)
from dfir_triage.schema import TIME_KEY_LAST_WRITE, TIME_LAST_EXECUTED


def test_run_keys_one_event_per_value():
    run = FakeKey(
        "Run",
        values={"Updater": "C:\\Users\\Public\\upd.exe", "OneDrive": "C:\\OneDrive.exe /bg"},
    )
    root = tree("Software\\Microsoft\\Windows\\CurrentVersion\\Run", run)

    events = parse_run_keys(root, NTUSER_RUN_KEYS, "NTUSER.DAT", user="bob")
    assert {e.details["value_name"] for e in events} == {"Updater", "OneDrive"}
    assert all(e.user == "bob" and e.event_type == "run_key" for e in events)
    assert all(e.time_meaning == TIME_KEY_LAST_WRITE for e in events)


def test_services_skip_keys_without_image_path():
    svc = FakeKey(
        "EvilSvc",
        values={"ImagePath": "cmd.exe /c C:\\Windows\\Temp\\p.exe", "Start": 2},
    )
    group = FakeKey("SomeDriverGroup", values={"Group": "x"})
    root = tree(
        "ControlSet001\\Services",
        FakeKey("Services", subkeys=[svc, group]),
        extra_root_subkeys=[select_key(1)],
    )

    [event] = parse_services(root, "SYSTEM")
    assert event.details["service"] == "EvilSvc"
    assert event.details["start_type"] == "auto"
    assert event.path.startswith("cmd.exe")


def test_decode_userassist_name_maps_known_folder():
    encoded = codecs.encode("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe", "rot_13")
    assert decode_userassist_name(encoded) == "C:\\Windows\\System32\\cmd.exe"


def test_userassist_parses_counts_and_skips_session_entry():
    last_run = datetime(2026, 4, 5, 6, 7, 8, tzinfo=UTC)
    name = codecs.encode("C:\\Tools\\procdump.exe", "rot_13")
    count = FakeKey(
        "Count",
        values={
            name: userassist_data(run_count=3, focus_ms=65_000, last_run=last_run),
            codecs.encode("UEME_CTLSESSION", "rot_13"): b"\x00" * 1612,
        },
    )
    guid = FakeKey("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", subkeys=[count])
    root = tree(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        FakeKey("UserAssist", subkeys=[guid]),
    )

    [event] = parse_userassist(root, "NTUSER.DAT", user="bob")
    assert event.path == "C:\\Tools\\procdump.exe"
    assert event.timestamp == last_run
    assert event.time_meaning == TIME_LAST_EXECUTED
    assert event.details["run_count"] == "3"
    assert event.details["focus_seconds"] == "65"
