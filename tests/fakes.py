"""In-memory stand-ins for python-registry keys and values.

They implement only the methods our parsers call, and raise the same
"not found" exceptions, so parser logic can be tested without binary hives.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta

from Registry import Registry

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def to_filetime(dt: datetime) -> int:
    return (dt - FILETIME_EPOCH) // timedelta(microseconds=1) * 10


class FakeValue:
    def __init__(self, name: str, data):
        self._name = name
        self._data = data

    def name(self):
        return self._name

    def value(self):
        return self._data


class FakeKey:
    def __init__(self, name: str, values=None, subkeys=None, timestamp=None):
        self._name = name
        self._values = [FakeValue(k, v) for k, v in (values or {}).items()]
        self._subkeys = list(subkeys or [])
        # python-registry returns naive UTC datetimes; mimic that.
        self._timestamp = timestamp or datetime(2026, 1, 1, 12, 0, 0)

    def name(self):
        return self._name

    def timestamp(self):
        return self._timestamp

    def values(self):
        return list(self._values)

    def subkeys(self):
        return list(self._subkeys)

    def value(self, name):
        for v in self._values:
            if v.name() == name:
                return v
        raise Registry.RegistryValueNotFoundException(name)

    def find_key(self, path):
        key = self
        for part in path.split("\\"):
            matches = [k for k in key._subkeys if k.name().lower() == part.lower()]
            if not matches:
                raise Registry.RegistryKeyNotFoundException(path)
            key = matches[0]
        return key


def tree(path: str, leaf: FakeKey, extra_root_subkeys=()) -> FakeKey:
    """Wrap `leaf` in parent keys so that root.find_key(path) returns it.

    `path` includes the leaf's own name as its last part.
    """
    parts = path.split("\\")
    assert parts[-1] == leaf.name()
    node = leaf
    for name in reversed(parts[:-1]):
        node = FakeKey(name, subkeys=[node])
    return FakeKey("ROOT", subkeys=[node, *extra_root_subkeys])


def select_key(current: int = 1) -> FakeKey:
    return FakeKey("Select", values={"Current": current})


def shimcache_blob(entries, header_size: int = 0x34) -> bytes:
    """Build a Windows 10 AppCompatCache value from (path, datetime) pairs."""
    blob = struct.pack("<I", header_size) + b"\x00" * (header_size - 4)
    for path, modified in entries:
        path_bytes = path.encode("utf-16-le")
        data = b"\x01\x02"  # opaque per-entry data
        body = (
            struct.pack("<H", len(path_bytes))
            + path_bytes
            + struct.pack("<Q", to_filetime(modified) if modified else 0)
            + struct.pack("<I", len(data))
            + data
        )
        blob += b"10ts" + struct.pack("<I", 0) + struct.pack("<I", len(body)) + body
    return blob


def userassist_data(run_count: int, focus_ms: int, last_run: datetime) -> bytes:
    data = bytearray(72)
    struct.pack_into("<I", data, 4, run_count)
    struct.pack_into("<I", data, 12, focus_ms)
    struct.pack_into("<Q", data, 60, to_filetime(last_run))
    return bytes(data)
