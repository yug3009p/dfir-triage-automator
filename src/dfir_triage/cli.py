"""Command line entry point.

    dfir-triage ./evidence -o ./out
    dfir-triage ./evidence -o ./out --summarize ollama

Writes timeline.csv, findings.csv and report.html into the output folder.
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path

from dfir_triage import __version__
from dfir_triage.report import DEFAULT_MAX_TIMELINE_ROWS, render_report, write_report
from dfir_triage.rules import Finding, run_rules
from dfir_triage.schema import format_timestamp
from dfir_triage.summarizer import PROVIDERS, summarize_timeline
from dfir_triage.timeline import build_timeline, to_dataframe, write_csv

FINDINGS_COLUMNS = [
    "severity",
    "rule_id",
    "title",
    "technique_id",
    "tactic",
    "timestamp",
    "time_meaning",
    "host",
    "user",
    "path",
    "description",
    "source",
    "event_id",
    "artifact",
]


def write_findings_csv(findings: list[Finding], out_path: Path) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FINDINGS_COLUMNS)
        writer.writeheader()
        for f in findings:
            e = f.event
            writer.writerow(
                {
                    "severity": f.rule.severity,
                    "rule_id": f.rule.id,
                    "title": f.rule.title,
                    "technique_id": f.rule.technique_id,
                    "tactic": f.rule.tactic,
                    "timestamp": format_timestamp(e.timestamp),
                    "time_meaning": e.time_meaning,
                    "host": e.host or "",
                    "user": e.user or "",
                    "path": e.path or "",
                    "description": e.description,
                    "source": e.source,
                    "event_id": "" if e.event_id is None else e.event_id,
                    "artifact": e.artifact,
                }
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfir-triage",
        description="Parse Windows artifacts into one timeline, run ATT&CK rules, write a report.",
    )
    parser.add_argument("evidence", type=Path, help="folder containing .evtx files and/or hives")
    parser.add_argument("-o", "--out", type=Path, default=Path("output"), help="output folder")
    parser.add_argument(
        "--summarize",
        choices=PROVIDERS,
        help="add an LLM-written summary (groq = hosted API, ollama = local model)",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=DEFAULT_MAX_TIMELINE_ROWS,
        help="timeline rows shown in the HTML report (CSV always has all rows)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="show parser warnings")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.ERROR, format="%(levelname)s %(message)s"
    )

    if not args.evidence.is_dir():
        print(f"error: evidence folder not found: {args.evidence}", file=sys.stderr)
        return 2

    events, artifacts = build_timeline(args.evidence)
    if not artifacts:
        print(f"error: no .evtx files or registry hives found in {args.evidence}", file=sys.stderr)
        return 2
    findings = run_rules(events)

    summary = None
    if args.summarize:
        summary = summarize_timeline(to_dataframe(events), findings, provider=args.summarize)
        if summary.startswith(("ERROR:", "STOP:")):
            print(summary, file=sys.stderr)
            summary = None  # still write the rest of the report

    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(events, args.out / "timeline.csv")
    write_findings_csv(findings, args.out / "findings.csv")
    html = render_report(
        events, findings, artifacts, str(args.evidence), summary, max_timeline_rows=args.max_rows
    )
    write_report(args.out / "report.html", html)

    failed = [a for a in artifacts if a.error]
    print(f"Parsed {len(artifacts) - len(failed)}/{len(artifacts)} artifacts, {len(events)} events")
    for a in failed:
        print(f"  failed: {a.path} ({a.error})")
    for severity in ("high", "medium", "low"):
        hits = [f for f in findings if f.rule.severity == severity]
        if hits:
            print(f"{severity.upper():6} {len(hits)} finding(s)")
            for f in hits[:5]:
                print(f"       {f.rule.id} {f.rule.title} @ {format_timestamp(f.event.timestamp)}")
    print(f"Wrote {args.out / 'report.html'}, timeline.csv, findings.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
