"""The one event shape every parser produces.

Each artifact type (event logs, Shimcache, Amcache, registry keys) records very
different things, so every parser converts its records into a TimelineEvent.
That is what lets us merge everything into a single, sortable timeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

# What a timestamp actually means differs per artifact. Mixing these up is one
# of the most common DFIR mistakes (e.g. reading a Shimcache time as "the
# program ran at"), so every event carries an explicit label.
TIME_EVENT_RECORDED = "EventRecorded"  # EVTX: when Windows wrote the event
TIME_FILE_MODIFIED = "FileLastModified"  # Shimcache: file's $SI modified time
TIME_KEY_LAST_WRITE = "KeyLastWrite"  # Registry: last write to the key (not the value)
TIME_LAST_EXECUTED = "LastExecuted"  # UserAssist: last run via Explorer

CSV_COLUMNS = [
    "timestamp",
    "time_meaning",
    "source",
    "event_type",
    "event_id",
    "host",
    "user",
    "path",
    "description",
    "details",
    "artifact",
]


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: datetime | None
    time_meaning: str
    source: str  # "evtx", "shimcache", "amcache", "registry", "userassist"
    event_type: str  # short machine-friendly label, e.g. "run_key", "service"
    description: str  # human-readable one-liner
    artifact: str  # file the event came from
    event_id: int | None = None
    host: str | None = None
    user: str | None = None
    path: str | None = None  # executable/file path when the artifact has one
    details: dict[str, str] = field(default_factory=dict)

    def to_row(self) -> dict[str, str]:
        """Flatten to strings for CSV/HTML output."""
        return {
            "timestamp": format_timestamp(self.timestamp),
            "time_meaning": self.time_meaning,
            "source": self.source,
            "event_type": self.event_type,
            "event_id": "" if self.event_id is None else str(self.event_id),
            "host": self.host or "",
            "user": self.user or "",
            "path": self.path or "",
            "description": self.description,
            "details": " | ".join(f"{k}={v}" for k, v in self.details.items()),
            "artifact": self.artifact,
        }


def as_utc(ts: datetime | None) -> datetime | None:
    """Windows stores times in UTC; libraries often hand them back naive."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC)


FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def filetime_to_datetime(filetime: int) -> datetime | None:
    """Windows FILETIME = 100-nanosecond ticks since 1601-01-01 UTC. 0 means "not set"."""
    if filetime <= 0:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    except OverflowError:
        return None


def format_timestamp(ts: datetime | None) -> str:
    if ts is None:
        return ""
    return as_utc(ts).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sort_key(event: TimelineEvent) -> tuple[bool, datetime]:
    """Sort by time; events with no timestamp go last."""
    if event.timestamp is None:
        return (True, datetime.min.replace(tzinfo=UTC))
    return (False, as_utc(event.timestamp))
