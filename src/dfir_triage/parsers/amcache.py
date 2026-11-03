"""Amcache.hve parser (Windows 10 1709+ / Windows 11 "Inventory" format).

Each subkey of Root\\InventoryApplicationFile describes one executable the
system inventoried, including its SHA-1. That hash is why analysts love
Amcache: you can look a binary up even after the attacker deleted it.

Timestamp: the subkey's last-write time. It is a good "first seen around"
indicator, but it is not a guaranteed execution time.
"""

from __future__ import annotations

from dfir_triage.hive import find_key, get_value
from dfir_triage.schema import TIME_KEY_LAST_WRITE, TimelineEvent, as_utc

INVENTORY_KEY = "Root\\InventoryApplicationFile"

# Amcache value name -> our details field name
FIELDS = {
    "Name": "name",
    "Publisher": "publisher",
    "Version": "version",
    "Size": "size",
    "LinkDate": "link_date",
    "ProductName": "product",
    "ProgramId": "program_id",
}


def sha1_from_file_id(file_id: str | None) -> str | None:
    """FileId is the SHA-1 prefixed with four zeros: '0000' + 40 hex chars."""
    if not file_id:
        return None
    file_id = file_id.strip().lower()
    if len(file_id) == 44 and file_id.startswith("0000"):
        return file_id[4:]
    return file_id or None


def parse_amcache(amcache_root, artifact: str, host: str | None = None) -> list[TimelineEvent]:
    inventory = find_key(amcache_root, INVENTORY_KEY)
    if inventory is None:
        return []

    events = []
    for entry in inventory.subkeys():
        details = {}
        for value_name, field in FIELDS.items():
            data = get_value(entry, value_name)
            if data not in (None, ""):
                details[field] = str(data)
        sha1 = sha1_from_file_id(get_value(entry, "FileId"))
        if sha1:
            details["sha1"] = sha1

        events.append(
            TimelineEvent(
                timestamp=as_utc(entry.timestamp()),
                time_meaning=TIME_KEY_LAST_WRITE,
                source="amcache",
                event_type="amcache_file",
                description="Amcache inventoried executable",
                artifact=artifact,
                host=host,
                path=get_value(entry, "LowerCaseLongPath"),
                details=details,
            )
        )
    return events
