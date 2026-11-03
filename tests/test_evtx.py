from datetime import UTC, datetime

from dfir_triage.parsers.evtx import describe, parse_evtx, parse_system_time, record_to_event
from dfir_triage.schema import TIME_EVENT_RECORDED

PTH_SAMPLE = "LateralMovement_LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx"
SYSMON_SAMPLE = "Execution_exec_driveby_cve-2018-15982_sysmon_1_10.evtx"

MINIMAL_RECORD = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>4624</EventID><TimeCreated SystemTime="2026-01-02 03:04:05.000001+00:00"/>
<Channel>Security</Channel><Computer>WS01</Computer></System>
<EventData><Data Name="TargetUserName">alice</Data><Data Name="LogonType">3</Data>
<Data Name="IpAddress">-</Data></EventData></Event>"""


def test_parse_system_time_handles_python_evtx_format():
    ts = parse_system_time("2019-03-18 11:06:25.485214+00:00")
    assert ts == datetime(2019, 3, 18, 11, 6, 25, 485214, tzinfo=UTC)


def test_parse_system_time_handles_zulu_and_garbage():
    assert parse_system_time("2019-03-18T11:06:25Z").tzinfo == UTC
    assert parse_system_time("not a time") is None
    assert parse_system_time(None) is None


def test_describe_keeps_sysmon_ids_separate():
    assert describe(1, "Microsoft-Windows-Sysmon/Operational") == "Sysmon: Process creation"
    assert describe(1, "Security") == "Other"
    assert describe(4624, "Security") == "Successful logon"


def test_record_to_event_extracts_fields_and_drops_dash_values():
    event = record_to_event(MINIMAL_RECORD, "x.evtx")
    assert event.event_id == 4624
    assert event.host == "WS01"
    assert event.user == "alice"
    assert event.time_meaning == TIME_EVENT_RECORDED
    assert event.details == {"TargetUserName": "alice", "LogonType": "3"}


def test_parse_pass_the_hash_sample(sample_data):
    events = parse_evtx(sample_data / PTH_SAMPLE)
    assert [e.event_id for e in events] == [1102, 4624, 4672, 4688, 4688, 4688]

    cleared = events[0]
    assert cleared.description == "Audit log cleared"
    # 1102 stores its fields under UserData, not EventData.
    assert "SubjectUserName" in cleared.details

    logon = events[1]
    assert logon.details["LogonType"] == "9"
    assert logon.details["LogonProcessName"] == "seclogo"


def test_parse_sysmon_sample_extracts_image_path(sample_data):
    events = parse_evtx(sample_data / SYSMON_SAMPLE)
    process = next(e for e in events if e.event_id == 1)
    assert process.path == "C:\\Windows\\System32\\cmd.exe"
    assert process.user == "IEWIN7\\IEUser"
