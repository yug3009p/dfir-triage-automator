"""Small helpers over python-registry.

The registry parsers only use a handful of key/value methods
(name, timestamp, subkeys, values, find_key, value). Keeping every lookup in
these helpers means the parsers can be unit-tested with tiny fake keys instead
of binary hive files.
"""

from __future__ import annotations

from pathlib import Path

from Registry import Registry


def open_hive(path: str | Path):
    """Return the root key of an offline hive file (SYSTEM, SOFTWARE, NTUSER.DAT, Amcache.hve)."""
    return Registry.Registry(str(path)).root()


def find_key(key, path: str):
    """Return the subkey at a backslash-separated path, or None if it does not exist."""
    try:
        return key.find_key(path)
    except Registry.RegistryKeyNotFoundException:
        return None


def get_value(key, name: str, default=None):
    """Return the data of a value, or `default` if the value does not exist."""
    try:
        return key.value(name).value()
    except Registry.RegistryValueNotFoundException:
        return default


def current_control_set(system_root) -> str:
    """SYSTEM\\Select\\Current says which ControlSet00N Windows booted with."""
    select = find_key(system_root, "Select")
    number = get_value(select, "Current", 1) if select is not None else 1
    return f"ControlSet{number:03d}"
