"""Persistence and user-activity keys from SYSTEM, SOFTWARE and NTUSER.DAT.

- Run / RunOnce (SOFTWARE and NTUSER.DAT): programs started at boot/logon.
- Services (SYSTEM): every installed service and the binary it launches.
- UserAssist (NTUSER.DAT): programs a user launched through Explorer, with a
  run count and last-run time. Value names are ROT13-encoded.

Registry timestamps belong to KEYS, not values. A Run key's last-write time
tells you when *something* in that key last changed, not when each value was added.
"""

from __future__ import annotations

import codecs
import struct

from dfir_triage.hive import current_control_set, find_key
from dfir_triage.schema import (
    TIME_KEY_LAST_WRITE,
    TIME_LAST_EXECUTED,
    TimelineEvent,
    as_utc,
    filetime_to_datetime,
)

# Paths relative to the hive root.
SOFTWARE_RUN_KEYS = (
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
)
NTUSER_RUN_KEYS = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
)
USERASSIST_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

SERVICE_START_TYPES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}

# A few Known Folder GUIDs that commonly prefix UserAssist paths.
KNOWN_FOLDERS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "C:\\Windows\\System32",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "C:\\Program Files",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "C:\\Program Files (x86)",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "C:\\Windows",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "C:\\Windows\\SysWOW64",
}
USERASSIST_DATA_SIZE = 72  # Windows 7 and later


def parse_run_keys(root, key_paths, artifact: str, user: str | None = None) -> list[TimelineEvent]:
    events = []
    for key_path in key_paths:
        key = find_key(root, key_path)
        if key is None:
            continue
        key_name = key_path.rsplit("\\", 1)[-1]
        for value in key.values():
            command = str(value.value())
            events.append(
                TimelineEvent(
                    timestamp=as_utc(key.timestamp()),
                    time_meaning=TIME_KEY_LAST_WRITE,
                    source="registry",
                    event_type="run_key",
                    description=f"Autorun entry '{value.name()}' in {key_name}",
                    artifact=artifact,
                    user=user,
                    path=command,
                    details={"key": key_path, "value_name": value.name(), "command": command},
                )
            )
    return events


def parse_services(system_root, artifact: str) -> list[TimelineEvent]:
    services = find_key(system_root, f"{current_control_set(system_root)}\\Services")
    if services is None:
        return []

    events = []
    for svc in services.subkeys():
        values = {v.name(): v.value() for v in svc.values()}
        image_path = values.get("ImagePath")
        if not image_path:
            continue  # driver groups / config-only keys have no binary to launch
        start = values.get("Start")
        details = {
            "service": svc.name(),
            "image_path": str(image_path),
            "start_type": SERVICE_START_TYPES.get(start, str(start)),
        }
        if values.get("DisplayName"):
            details["display_name"] = str(values["DisplayName"])
        if values.get("ObjectName"):
            details["account"] = str(values["ObjectName"])
        events.append(
            TimelineEvent(
                timestamp=as_utc(svc.timestamp()),
                time_meaning=TIME_KEY_LAST_WRITE,
                source="registry",
                event_type="service",
                description=f"Service '{svc.name()}' ({details['start_type']} start)",
                artifact=artifact,
                path=str(image_path),
                details=details,
            )
        )
    return events


def decode_userassist_name(encoded: str) -> str:
    name = codecs.decode(encoded, "rot_13")
    for guid, folder in KNOWN_FOLDERS.items():
        if name.upper().startswith(guid):
            return folder + name[len(guid) :]
    return name


def parse_userassist(ntuser_root, artifact: str, user: str | None = None) -> list[TimelineEvent]:
    userassist = find_key(ntuser_root, USERASSIST_KEY)
    if userassist is None:
        return []

    events = []
    for guid_key in userassist.subkeys():
        count_key = find_key(guid_key, "Count")
        if count_key is None:
            continue
        for value in count_key.values():
            data = value.value()
            if not isinstance(data, bytes) or len(data) != USERASSIST_DATA_SIZE:
                continue  # e.g. the UEME_CTLSESSION bookkeeping entry
            (run_count,) = struct.unpack_from("<I", data, 4)
            (focus_ms,) = struct.unpack_from("<I", data, 12)
            (last_run,) = struct.unpack_from("<Q", data, 60)
            path = decode_userassist_name(value.name())
            events.append(
                TimelineEvent(
                    timestamp=filetime_to_datetime(last_run),
                    time_meaning=TIME_LAST_EXECUTED,
                    source="userassist",
                    event_type="userassist",
                    description=f"Launched via Explorer ({run_count} run(s))",
                    artifact=artifact,
                    user=user,
                    path=path,
                    details={
                        "run_count": str(run_count),
                        "focus_seconds": str(focus_ms // 1000),
                        "guid": guid_key.name(),
                    },
                )
            )
    return events
