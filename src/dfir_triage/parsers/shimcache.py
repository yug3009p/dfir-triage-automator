"""Shimcache (AppCompatCache) parser for Windows 10 / 11 SYSTEM hives.

Shimcache lives in one binary value:
    SYSTEM\\ControlSet00N\\Control\\Session Manager\\AppCompatCache\\AppCompatCache

Important for interpretation: on Windows 10/11 an entry proves the file
EXISTED and was seen by the compatibility engine. It does NOT prove it ran,
and the timestamp is the file's last-modified time, not an execution time.

Binary layout (Windows 10/11):
    header:  DWORD header_size (0x30 or 0x34), entries start at that offset
    entry:   "10ts" signature (4) | unknown (4) | entry_size (4)
             path_size (2) | path UTF-16LE (path_size)
             last_modified FILETIME (8) | data_size (4) | data (data_size)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime

from dfir_triage.hive import current_control_set, find_key, get_value
from dfir_triage.schema import TIME_FILE_MODIFIED, TimelineEvent, filetime_to_datetime

SIGNATURE = b"10ts"
SUPPORTED_HEADER_SIZES = (0x30, 0x34)


class UnsupportedShimcacheFormat(ValueError):
    pass


@dataclass(frozen=True)
class ShimcacheEntry:
    position: int  # 0 = most recently added/updated entry
    path: str
    last_modified: datetime | None


def parse_appcompatcache(blob: bytes) -> list[ShimcacheEntry]:
    if len(blob) < 4:
        raise UnsupportedShimcacheFormat("value too short")
    (header_size,) = struct.unpack_from("<I", blob, 0)
    if header_size not in SUPPORTED_HEADER_SIZES:
        raise UnsupportedShimcacheFormat(
            f"header size 0x{header_size:x} is not Windows 10/11 (expected 0x30 or 0x34)"
        )

    entries = []
    offset = header_size
    while offset + 12 <= len(blob):
        if blob[offset : offset + 4] != SIGNATURE:
            break  # end of entries (or trailing garbage)
        (entry_size,) = struct.unpack_from("<I", blob, offset + 8)
        body = offset + 12
        (path_size,) = struct.unpack_from("<H", blob, body)
        path = blob[body + 2 : body + 2 + path_size].decode("utf-16-le", errors="replace")
        (filetime,) = struct.unpack_from("<Q", blob, body + 2 + path_size)
        entries.append(ShimcacheEntry(len(entries), path, filetime_to_datetime(filetime)))
        offset = body + entry_size
    return entries


def parse_shimcache(system_root, artifact: str, host: str | None = None) -> list[TimelineEvent]:
    key_path = f"{current_control_set(system_root)}\\Control\\Session Manager\\AppCompatCache"
    key = find_key(system_root, key_path)
    blob = get_value(key, "AppCompatCache") if key is not None else None
    if not blob:
        return []
    return [
        TimelineEvent(
            timestamp=entry.last_modified,
            time_meaning=TIME_FILE_MODIFIED,
            source="shimcache",
            event_type="shimcache_entry",
            description="Shimcache entry (file present on system; not proof of execution)",
            artifact=artifact,
            host=host,
            path=entry.path,
            details={"cache_position": str(entry.position)},
        )
        for entry in parse_appcompatcache(blob)
    ]
