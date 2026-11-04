"""Check a lab run's dfir-triage results against ground truth, and optionally against
Eric Zimmerman's tools. Writes validation-results.md into the run folder.

    python lab/compare.py lab-runs/<timestamp>

Ground truth comes from inside the VM (guest/activity.ps1): the real SHA-1 and
last-modified time of each planted file, and which rules each step should trigger.
That makes the parser checks independent of any other tool.

Status per check: PASS, FAIL (exit code 1), or WARN (worth a look, does not fail the run).
"""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dfir_triage.rules import Finding, run_rules
from dfir_triage.schema import TimelineEvent
from dfir_triage.timeline import ArtifactResult, build_timeline


@dataclass
class Check:
    name: str
    status: str  # PASS | FAIL | WARN
    detail: str


def parse_utc(text: str) -> datetime | None:
    if not text:
        return None
    text = text.strip().replace("Z", "+00:00")
    # PowerShell writes 7 fractional digits; Python accepts at most 6.
    if "." in text:
        head, rest = text.split(".", 1)
        digits = "".join(c for c in rest if c.isdigit())
        tz = rest[len(digits) :]
        text = f"{head}.{digits[:6]}{tz}"
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            dt = datetime.fromisoformat(text) if fmt is None else datetime.strptime(text, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def same_second(a: datetime | None, b: datetime | None) -> bool:
    return a is not None and b is not None and abs((a - b).total_seconds()) < 1


def _ends(path: str | None, name: str) -> bool:
    return bool(path) and path.lower().replace("/", "\\").endswith(name.lower())


def check_coverage(artifacts: list[ArtifactResult]) -> list[Check]:
    kinds = {a.kind for a in artifacts}
    checks = []
    for kind in ("evtx", "system_hive", "software_hive", "ntuser_hive", "amcache_hive"):
        failed = [a for a in artifacts if a.kind == kind and a.error]
        if kind not in kinds:
            checks.append(Check(f"artifact parsed: {kind}", "FAIL", "not found in evidence"))
        elif failed:
            checks.append(Check(f"artifact parsed: {kind}", "FAIL", failed[0].error or ""))
        else:
            n = sum(a.events for a in artifacts if a.kind == kind)
            checks.append(Check(f"artifact parsed: {kind}", "PASS", f"{n} events"))
    return checks


def check_rules(truth: dict, findings: list[Finding]) -> list[Check]:
    # Only findings from the lab activity count: Windows Setup itself creates accounts and
    # services, which would make a rule "pass" even if the lab step had silently failed.
    # Findings whose time is a file's own modified time say nothing about when it ran, so skip them.
    started = parse_utc(truth["started_utc"]) - timedelta(seconds=60)
    fired = {
        f.rule.id
        for f in findings
        if f.event.time_meaning != "FileLastModified" and f.event.timestamp >= started
    }
    before = {f.rule.id for f in findings} - fired
    expected = sorted({r for step in truth["steps"] for r in step.get("expected_rules", [])})
    checks = []
    for rid in expected:
        if rid in fired:
            checks.append(Check(f"rule fired: {rid}", "PASS", "on lab activity"))
        elif rid in before:
            detail = "only on events from before the lab activity"
            checks.append(Check(f"rule fired: {rid}", "FAIL", detail))
        else:
            checks.append(Check(f"rule fired: {rid}", "FAIL", "expected from lab activity"))
    return checks


def check_parsers(truth: dict, events: list[TimelineEvent]) -> list[Check]:
    steps = {s["name"]: s["data"] for s in truth["steps"]}
    stage = steps["run_from_public"]["stage"]
    checks = []

    # Shimcache: the entry exists and its time equals the file's real last-modified time.
    shim = [e for e in events if e.source == "shimcache" and _ends(e.path, "stage.exe")]
    if not shim:
        checks.append(
            Check("shimcache: stage.exe present", "FAIL", "no Shimcache entry for stage.exe")
        )
    else:
        ok = same_second(shim[0].timestamp, parse_utc(stage["last_write_utc"]))
        checks.append(
            Check(
                "shimcache: stage.exe present",
                "PASS",
                f"cache position {shim[0].details.get('cache_position')}",
            )
        )
        checks.append(
            Check(
                "shimcache: timestamp = file last-modified time",
                "PASS" if ok else "FAIL",
                f"parsed {shim[0].timestamp}, real {stage['last_write_utc']}",
            )
        )

    # Amcache: Windows decides when to inventory a file, so absence is only a warning,
    # but a wrong hash is a failure.
    for key in ("stage", "setup"):
        facts = steps["run_from_public"][key]
        name = Path(facts["path"].replace("\\", "/")).name
        rows = [e for e in events if e.source == "amcache" and _ends(e.path, name)]
        if not rows:
            checks.append(
                Check(f"amcache: {name} present", "WARN", "not inventoried by Windows in this run")
            )
            continue
        sha1 = rows[0].details.get("sha1", "")
        checks.append(
            Check(
                f"amcache: {name} SHA-1 = real file SHA-1",
                "PASS" if sha1 == facts["sha1"] else "FAIL",
                f"parsed {sha1 or '(none)'}, real {facts['sha1']}",
            )
        )

    run = steps["run_key"]
    hit = any(
        e.event_type == "run_key"
        and e.details.get("value_name") == run["value_name"]
        and e.details.get("command") == run["command"]
        for e in events
    )
    checks.append(Check("registry: Run key LabUpdater", "PASS" if hit else "FAIL", run["command"]))

    svc = steps["service"]
    hit = any(
        e.event_type == "service"
        and e.details.get("service") == svc["service"]
        and e.details.get("image_path") == svc["image_path"]
        for e in events
    )
    checks.append(Check("registry: service LabSvc", "PASS" if hit else "FAIL", svc["image_path"]))

    ua = [e for e in events if e.source == "userassist" and _ends(e.path, "setup.exe")]
    checks.append(
        Check(
            "userassist: setup.exe launch",
            "PASS" if ua else "WARN",
            f"run count {ua[0].details.get('run_count')}"
            if ua
            else "Explorer launch from a scripted session may not be recorded",
        )
    )
    return checks


def _read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def _column(rows: list[dict[str, str]], *candidates: str) -> str | None:
    if not rows:
        return None
    lowered = {c.lower(): c for c in rows[0]}
    return next((lowered[c.lower()] for c in candidates if c.lower() in lowered), None)


def check_against_ez(events: list[TimelineEvent], ez_dir: Path) -> list[Check]:
    checks = []
    ours = {e.path.lower(): e for e in events if e.source == "shimcache" and e.path}

    shim_csv = next(iter(sorted(ez_dir.glob("*shimcache*.csv"))), None) or next(
        iter(sorted(ez_dir.glob("*AppCompat*.csv"))), None
    )
    if shim_csv:
        rows = _read_csv(shim_csv)
        path_col, time_col, set_col = (
            _column(rows, "Path"),
            _column(rows, "LastModifiedTimeUTC"),
            _column(rows, "ControlSet"),
        )
        if not path_col:
            checks.append(
                Check("EZ shimcache: columns", "WARN", f"unexpected columns in {shim_csv.name}")
            )
        else:
            if (
                set_col
            ):  # EZ reports every control set; compare with the one closest in size to ours
                groups: dict[str, list[dict[str, str]]] = {}
                for r in rows:
                    groups.setdefault(r[set_col], []).append(r)
                rows = min(groups.values(), key=lambda g: abs(len(g) - len(ours)))
            theirs = {r[path_col].lower(): r for r in rows if r[path_col]}
            missing, extra = sorted(set(theirs) - set(ours)), sorted(set(ours) - set(theirs))
            checks.append(
                Check(
                    "EZ shimcache: same entries",
                    "PASS" if not missing and not extra else "FAIL",
                    f"ours {len(ours)}, AppCompatCacheParser {len(theirs)}; "
                    f"missing {missing[:3]}, extra {extra[:3]}",
                )
            )
            if time_col:
                bad = [
                    p
                    for p in set(ours) & set(theirs)
                    if not same_second(ours[p].timestamp, parse_utc(theirs[p][time_col]))
                ]
                checks.append(
                    Check(
                        "EZ shimcache: same timestamps",
                        "PASS" if not bad else "FAIL",
                        f"{len(bad)} differ {bad[:3]}",
                    )
                )
    else:
        checks.append(Check("EZ shimcache", "WARN", "no AppCompatCacheParser CSV found"))

    amcache_csvs = [p for p in ez_dir.glob("*.csv") if "FileEntries" in p.name]
    if amcache_csvs:
        theirs_sha1 = set()
        for p in amcache_csvs:
            rows = _read_csv(p)
            col = _column(rows, "SHA1")
            theirs_sha1 |= {r[col].lower() for r in rows if col and r[col]}
        ours_sha1 = {
            e.details["sha1"] for e in events if e.source == "amcache" and e.details.get("sha1")
        }
        missing = theirs_sha1 - ours_sha1
        checks.append(
            Check(
                "EZ amcache: same SHA-1 set",
                "PASS" if not missing else "FAIL",
                f"ours {len(ours_sha1)}, AmcacheParser {len(theirs_sha1)}, "
                f"missing from ours {len(missing)}",
            )
        )
    else:
        checks.append(Check("EZ amcache", "WARN", "no AmcacheParser FileEntries CSV found"))
    return checks


def write_report(run_dir: Path, truth: dict, checks: list[Check]) -> Path:
    counts = {s: sum(c.status == s for c in checks) for s in ("PASS", "FAIL", "WARN")}
    lines = [
        "# Lab validation results",
        "",
        f"- Run: `{run_dir.name}`  |  Lab host: `{truth.get('hostname')}`  |  "
        f"Activity started {truth.get('started_utc')}",
        f"- **{counts['PASS']} passed, {counts['FAIL']} failed, {counts['WARN']} warnings**",
        "",
        "| Check | Status | Detail |",
        "|---|---|---|",
        *[f"| {c.name} | {c.status} | {c.detail.replace('|', '/')} |" for c in checks],
        "",
    ]
    out = run_dir / "validation-results.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def main(run_dir: str) -> int:
    run = Path(run_dir)
    evidence = run / "evidence"
    truth = json.loads((evidence / "ground-truth.json").read_text(encoding="utf-8-sig"))
    events, artifacts = build_timeline(evidence)
    findings = run_rules(events)

    checks = check_coverage(artifacts) + check_rules(truth, findings) + check_parsers(truth, events)
    if (run / "ez").is_dir():
        checks += check_against_ez(events, run / "ez")

    report = write_report(run, truth, checks)
    for c in checks:
        print(f"{c.status:4}  {c.name}  {c.detail}")
    print(f"\nReport: {report}")
    return 1 if any(c.status == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python lab/compare.py <run-folder>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
