"""Windows event log (.evtx) parser.

python-evtx gives us each record as an XML string. We pull out the System
header (time, event ID, channel, computer) and the EventData/UserData fields,
then translate the event ID into plain English.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from Evtx.Evtx import Evtx

from dfir_triage.schema import TIME_EVENT_RECORDED, TimelineEvent, as_utc

log = logging.getLogger(__name__)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

SECURITY_DESCRIPTIONS = {
    104: "Event log cleared (System)",
    1102: "Audit log cleared",
    4104: "PowerShell script block",
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4648: "Explicit-credential logon",
    4672: "Special privileges assigned",
    4688: "Process creation",
    4697: "Service installed (Security)",
    4698: "Scheduled task created",
    4720: "User account created",
    4724: "Password reset",
    4728: "Added to security-enabled global group",
    4732: "Added to security-enabled local group",
    4740: "Account locked out",
    4756: "Added to security-enabled universal group",
    7036: "Service state change",
    7045: "Service installed (System)",
}

# Sysmon reuses small numbers that collide with other channels, so it gets its own table.
SYSMON_DESCRIPTIONS = {
    1: "Sysmon: Process creation",
    3: "Sysmon: Network connection",
    7: "Sysmon: Image loaded",
    8: "Sysmon: CreateRemoteThread",
    10: "Sysmon: Process access",
    11: "Sysmon: File create",
    13: "Sysmon: Registry value set",
    22: "Sysmon: DNS query",
}

# Field names that hold the account an event is "about", in order of preference.
USER_FIELDS = ("TargetUserName", "User", "SubjectUserName")
# Field names that hold an executable path.
PATH_FIELDS = ("Image", "NewProcessName", "ImagePath", "ServiceFileName")


def describe(event_id: int | None, channel: str) -> str:
    if event_id is None:
        return "Other"
    if "Sysmon" in channel:
        return SYSMON_DESCRIPTIONS.get(event_id, "Other")
    return SECURITY_DESCRIPTIONS.get(event_id, "Other")


def parse_system_time(raw: str | None) -> datetime | None:
    """python-evtx emits e.g. '2019-03-18 11:06:25.485214+00:00'."""
    if not raw:
        return None
    try:
        return as_utc(datetime.fromisoformat(raw.replace("Z", "+00:00")))
    except ValueError:
        return None


def extract_fields(root: ET.Element) -> dict[str, str]:
    """Collect name=value pairs from EventData, or from UserData (used by e.g. 1102)."""
    fields: dict[str, str] = {}
    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        for i, data in enumerate(event_data.findall("e:Data", NS)):
            value = (data.text or "").strip()
            if value and value != "-":
                fields[data.get("Name") or f"Data{i}"] = value
    user_data = root.find("e:UserData", NS)
    if user_data is not None:
        # UserData has one wrapper element (e.g. <LogFileCleared>) holding the fields.
        for wrapper in user_data:
            for child in wrapper:
                value = (child.text or "").strip()
                if value:
                    fields[child.tag.split("}")[-1]] = value
    return fields


def _first(fields: dict[str, str], names: tuple[str, ...]) -> str | None:
    for name in names:
        if fields.get(name):
            return fields[name]
    return None


def record_to_event(xml: str, artifact: str) -> TimelineEvent:
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    if system is None:
        raise ValueError("record has no System element")

    event_id_el = system.find("e:EventID", NS)
    event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else None
    time_el = system.find("e:TimeCreated", NS)
    channel_el = system.find("e:Channel", NS)
    computer_el = system.find("e:Computer", NS)
    channel = (channel_el.text or "") if channel_el is not None else ""

    fields = extract_fields(root)
    return TimelineEvent(
        timestamp=parse_system_time(time_el.get("SystemTime") if time_el is not None else None),
        time_meaning=TIME_EVENT_RECORDED,
        source="evtx",
        event_type=channel or "unknown",
        description=describe(event_id, channel),
        artifact=artifact,
        event_id=event_id,
        host=computer_el.text if computer_el is not None else None,
        user=_first(fields, USER_FIELDS),
        path=_first(fields, PATH_FIELDS),
        details=fields,
    )


def parse_evtx(file_path: str | Path) -> list[TimelineEvent]:
    """Parse every record in an .evtx file. Bad records are counted and logged, not fatal."""
    artifact = str(file_path)
    events: list[TimelineEvent] = []
    skipped = 0
    with Evtx(artifact) as evtx_file:
        for record in evtx_file.records():
            try:
                events.append(record_to_event(record.xml(), artifact))
            except Exception as exc:  # one corrupt record should not kill the whole file
                skipped += 1
                log.debug("skipping record in %s: %s", artifact, exc)
    if skipped:
        log.warning("%s: skipped %d unreadable record(s)", artifact, skipped)
    return events
