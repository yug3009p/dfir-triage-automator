import sys
import xml.etree.ElementTree as ET
from datetime import datetime

import pandas as pd
from Evtx.Evtx import Evtx

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

EVENT_DESCRIPTIONS = {
    # Windows Security
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4648: "Explicit-credential logon",
    4672: "Special privileges assigned",
    4688: "Process creation",
    4720: "User account created",
    4724: "Password reset",
    4728: "Added to security-enabled global group",
    4732: "Added to security-enabled local group",
    4756: "Added to security-enabled universal group",
    4740: "Account locked out",
    1102: "Audit log cleared",
    4698: "Scheduled task created",
    4697: "Service installed (Security)",
    7045: "Service installed (System)",
    7036: "Service state change",
    # PowerShell
    4104: "PowerShell script block",
}

SYSMON_DESCRIPTIONS = {
    1: "Sysmon: Process creation",
    3: "Sysmon: Network connection",
    11: "Sysmon: File create",
    13: "Sysmon: Registry value set",
}


def _describe(event_id: int, channel: str) -> str:
    if channel and "Sysmon" in channel and event_id in SYSMON_DESCRIPTIONS:
        return SYSMON_DESCRIPTIONS[event_id]
    return EVENT_DESCRIPTIONS.get(event_id, "Other")


def _parse_timestamp(raw: str):
    if not raw:
        return None
    cleaned = raw.rstrip("Z")
    if "." in cleaned:
        head, frac = cleaned.split(".", 1)
        frac = frac[:6].ljust(6, "0")
        cleaned = f"{head}.{frac}"
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return pd.to_datetime(raw, errors="coerce", utc=False)


def _text(elem, path: str):
    if elem is None:
        return None
    found = elem.find(path, NS)
    return found.text if found is not None else None


def _attr(elem, path: str, attr: str):
    if elem is None:
        return None
    found = elem.find(path, NS)
    return found.get(attr) if found is not None else None


def _build_details(event_data) -> str:
    if event_data is None:
        return ""
    parts = []
    for data in event_data.findall("e:Data", NS):
        name = data.get("Name")
        value = (data.text or "").strip()
        if not value or value == "-":
            continue
        if name:
            parts.append(f"{name}={value}")
        else:
            parts.append(value)
    return " | ".join(parts)


def parse_evtx(file_path: str) -> pd.DataFrame:
    rows = []
    with Evtx(file_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                system = root.find("e:System", NS)
                event_data = root.find("e:EventData", NS)

                event_id_text = _text(system, "e:EventID")
                event_id = int(event_id_text) if event_id_text else None

                ts_raw = _attr(system, "e:TimeCreated", "SystemTime")
                timestamp = _parse_timestamp(ts_raw)

                channel = _text(system, "e:Channel")
                provider = _attr(system, "e:Provider", "Name")
                computer = _text(system, "e:Computer")
                details = _build_details(event_data)

                rows.append(
                    {
                        "timestamp": timestamp,
                        "event_id": event_id,
                        "channel": channel,
                        "provider": provider,
                        "computer": computer,
                        "details": details,
                        "description": _describe(event_id, channel or provider or ""),
                    }
                )
            except Exception:
                continue

    df = pd.DataFrame(
        rows,
        columns=[
            "timestamp",
            "event_id",
            "channel",
            "provider",
            "computer",
            "details",
            "description",
        ],
    )
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.sort_values("timestamp", ascending=True, na_position="last").reset_index(drop=True)
    return df


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parser.py <path-to-evtx>")
        sys.exit(1)

    path = sys.argv[1]
    df = parse_evtx(path)
    print(f"Total records: {len(df)}")
    with pd.option_context("display.max_columns", None, "display.width", 200):
        print(df.head(20))
