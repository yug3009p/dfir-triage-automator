"""Render a single, self-contained HTML triage report.

Everything in the evidence (usernames, command lines, paths) is attacker-
controlled, so the template is rendered with autoescaping ON: a log field
containing "<script>" shows up as text, never runs in the analyst's browser.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from dfir_triage import __version__
from dfir_triage.rules import Finding
from dfir_triage.schema import TimelineEvent, format_timestamp
from dfir_triage.timeline import ArtifactResult

DEFAULT_MAX_TIMELINE_ROWS = 5000


def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("dfir_triage", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
    )
    env.filters["ts"] = format_timestamp
    return env


def attack_url(technique_id: str) -> str:
    """T1070.001 -> https://attack.mitre.org/techniques/T1070/001/"""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def render_report(
    events: list[TimelineEvent],
    findings: list[Finding],
    artifacts: list[ArtifactResult],
    evidence_dir: str,
    summary: str | None = None,
    max_timeline_rows: int = DEFAULT_MAX_TIMELINE_ROWS,
) -> str:
    severity_counts = Counter(f.rule.severity for f in findings)
    timestamps = [e.timestamp for e in events if e.timestamp is not None]
    return (
        _environment()
        .get_template("report.html.j2")
        .render(
            version=__version__,
            generated=datetime.now(UTC),
            evidence_dir=evidence_dir,
            events=events[:max_timeline_rows],
            total_events=len(events),
            truncated=len(events) > max_timeline_rows,
            first_seen=min(timestamps, default=None),
            last_seen=max(timestamps, default=None),
            findings=findings,
            severity_counts={s: severity_counts.get(s, 0) for s in ("high", "medium", "low")},
            artifacts=artifacts,
            failed_artifacts=sum(1 for a in artifacts if a.error),
            summary=summary,
            attack_url=attack_url,
        )
    )


def write_report(path: str | Path, html: str) -> None:
    Path(path).write_text(html, encoding="utf-8")
