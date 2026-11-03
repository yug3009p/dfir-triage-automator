"""Find artifacts in an evidence folder, run the right parser on each, merge the results.

Artifacts are recognised by file name (case-insensitive), so any folder layout
works: a KAPE output tree, a flat folder of copied files, etc.
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass, replace
from pathlib import Path

import pandas as pd

from dfir_triage.hive import current_control_set, find_key, get_value, open_hive
from dfir_triage.parsers.amcache import parse_amcache
from dfir_triage.parsers.evtx import parse_evtx
from dfir_triage.parsers.registry import (
    NTUSER_RUN_KEYS,
    SOFTWARE_RUN_KEYS,
    parse_run_keys,
    parse_services,
    parse_userassist,
)
from dfir_triage.parsers.shimcache import parse_shimcache
from dfir_triage.schema import CSV_COLUMNS, TimelineEvent, sort_key

log = logging.getLogger(__name__)


@dataclass
class ArtifactResult:
    """What happened to one input file. Shown in the report so gaps are visible."""

    path: str
    kind: str
    events: int = 0
    error: str | None = None


def classify(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".evtx"):
        return "evtx"
    if name == "system":
        return "system_hive"
    if name == "software":
        return "software_hive"
    if name == "ntuser.dat":
        return "ntuser_hive"
    if name == "amcache.hve":
        return "amcache_hive"
    return None


def hostname_from_system(system_root) -> str | None:
    key = find_key(
        system_root,
        f"{current_control_set(system_root)}\\Control\\ComputerName\\ComputerName",
    )
    return get_value(key, "ComputerName") if key is not None else None


def parse_artifact(path: Path, kind: str) -> list[TimelineEvent]:
    artifact = str(path)
    if kind == "evtx":
        return parse_evtx(path)
    root = open_hive(path)
    if kind == "system_hive":
        host = hostname_from_system(root)
        events = parse_shimcache(root, artifact, host) + parse_services(root, artifact)
        return [_with_host(e, host) for e in events]
    if kind == "software_hive":
        return parse_run_keys(root, SOFTWARE_RUN_KEYS, artifact)
    if kind == "ntuser_hive":
        user = path.parent.name  # .../Users/<name>/NTUSER.DAT
        return parse_run_keys(root, NTUSER_RUN_KEYS, artifact, user) + parse_userassist(
            root, artifact, user
        )
    if kind == "amcache_hive":
        return parse_amcache(root, artifact)
    raise ValueError(f"unknown artifact kind: {kind}")


def _with_host(event: TimelineEvent, host: str | None) -> TimelineEvent:
    if event.host or not host:
        return event
    # TimelineEvent is frozen (immutable), so make a copy with the host filled in.
    return replace(event, host=host)


def build_timeline(evidence_dir: str | Path) -> tuple[list[TimelineEvent], list[ArtifactResult]]:
    """Parse every recognised artifact under evidence_dir. One bad file never stops the run."""
    events: list[TimelineEvent] = []
    results: list[ArtifactResult] = []
    for path in sorted(Path(evidence_dir).rglob("*")):
        kind = classify(path) if path.is_file() else None
        if kind is None:
            continue
        result = ArtifactResult(path=str(path), kind=kind)
        try:
            parsed = parse_artifact(path, kind)
            events.extend(parsed)
            result.events = len(parsed)
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            log.warning("failed to parse %s: %s", path, result.error)
        results.append(result)
    events.sort(key=sort_key)
    return events, results


def to_dataframe(events: list[TimelineEvent]) -> pd.DataFrame:
    """Table view for the Streamlit UI and LLM summarizer. Keeps real datetimes for sorting."""
    rows = []
    for event in events:
        row = event.to_row()
        row["timestamp"] = event.timestamp
        row["event_id"] = event.event_id
        rows.append(row)
    return pd.DataFrame(rows, columns=CSV_COLUMNS)


def write_csv(events: list[TimelineEvent], out_path: str | Path) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for event in events:
            writer.writerow(event.to_row())
