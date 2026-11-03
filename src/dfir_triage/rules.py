"""Deterministic detection rules mapped to MITRE ATT&CK.

Each rule is a plain Python function over one TimelineEvent. No LLM is
involved: the same evidence always produces the same findings, and every
finding points back to the exact event that triggered it.

Rules flag things worth an analyst's attention, not proven malice. Each
rule's `note` says what commonly causes benign hits.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from dfir_triage.schema import TimelineEvent, sort_key

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Folders any user can write to. Programs running from here deserve a look.
USER_WRITABLE_DIRS = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\$recycle.bin\\",
)

# PowerShell accepts any prefix of -EncodedCommand (-e, -en, -enc, ...) plus the alias -ec.
_ENCODED_FLAGS = ["ec"] + ["encodedcommand"[:n] for n in range(1, len("encodedcommand") + 1)]
# Matches e.g. "powershell.exe -nop -enc SQBFAFgA..." and "pwsh -ec SQBFAFgA..."
ENCODED_POWERSHELL = re.compile(
    r"(?:powershell|pwsh)(?:\.exe)?\"?(?:\s+\S+)*?\s+[-/](?:"
    + "|".join(sorted(_ENCODED_FLAGS, key=len, reverse=True))
    + r")\s+[a-z0-9+/=]{16,}",
    re.IGNORECASE,
)

# Service binaries launched through a shell or script host are a classic persistence trick.
SUSPICIOUS_SERVICE_COMMAND = re.compile(
    r"(?:cmd(?:\.exe)?\s+/c|powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript)",
    re.IGNORECASE,
)

PROCESS_CREATION = {("security", 4688), ("sysmon", 1)}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    technique_id: str
    technique: str
    tactic: str
    severity: str  # "high" | "medium" | "low"
    note: str  # common benign causes / how to triage
    match: Callable[[TimelineEvent], bool]


@dataclass(frozen=True)
class Finding:
    rule: Rule
    event: TimelineEvent


# ---------------------------------------------------------------- helpers


def _channel(event: TimelineEvent) -> str:
    """'sysmon', 'security', 'system', ... for EVTX events; '' otherwise."""
    if event.source != "evtx":
        return ""
    channel = event.event_type.lower()
    return "sysmon" if "sysmon" in channel else channel.split("/")[0]


def _is(event: TimelineEvent, channel: str, *event_ids: int) -> bool:
    return _channel(event) == channel and event.event_id in event_ids


def _field(event: TimelineEvent, name: str) -> str:
    return event.details.get(name, "").strip()


def _command_line(event: TimelineEvent) -> str:
    return _field(event, "CommandLine")


def _in_user_writable_dir(path: str | None) -> bool:
    if not path:
        return False
    lowered = path.lower().replace("/", "\\")
    return any(d in lowered for d in USER_WRITABLE_DIRS)


def _service_binary(event: TimelineEvent) -> str:
    """The binary a new/installed service launches, from EVTX or the SYSTEM hive."""
    if event.source == "registry" and event.event_type == "service":
        return _field(event, "image_path")
    if _is(event, "system", 7045):
        return _field(event, "ImagePath")
    if _is(event, "security", 4697):
        return _field(event, "ServiceFileName")
    return ""


# ---------------------------------------------------------------- rules


def _log_cleared(e: TimelineEvent) -> bool:
    return _is(e, "security", 1102) or _is(e, "system", 104)


def _pass_the_hash_logon(e: TimelineEvent) -> bool:
    # Logon type 9 (NewCredentials) via seclogo is what sekurlsa::pth and runas /netonly produce.
    return (
        _is(e, "security", 4624)
        and _field(e, "LogonType") == "9"
        and _field(e, "LogonProcessName").lower() == "seclogo"
    )


def _lsass_access(e: TimelineEvent) -> bool:
    return _is(e, "sysmon", 10) and _field(e, "TargetImage").lower().endswith("\\lsass.exe")


def _encoded_powershell(e: TimelineEvent) -> bool:
    is_process = (_channel(e), e.event_id) in PROCESS_CREATION
    return is_process and bool(ENCODED_POWERSHELL.search(_command_line(e)))


def _service_installed(e: TimelineEvent) -> bool:
    return _is(e, "system", 7045) or _is(e, "security", 4697)


def _suspicious_service_binary(e: TimelineEvent) -> bool:
    binary = _service_binary(e)
    return bool(binary) and (
        bool(SUSPICIOUS_SERVICE_COMMAND.search(binary)) or _in_user_writable_dir(binary)
    )


def _scheduled_task_created(e: TimelineEvent) -> bool:
    return _is(e, "security", 4698)


def _account_created(e: TimelineEvent) -> bool:
    return _is(e, "security", 4720)


def _added_to_group(e: TimelineEvent) -> bool:
    return _is(e, "security", 4728, 4732, 4756)


def _run_key(e: TimelineEvent) -> bool:
    return e.source == "registry" and e.event_type == "run_key"


def _execution_from_user_writable_dir(e: TimelineEvent) -> bool:
    is_process = (_channel(e), e.event_id) in PROCESS_CREATION
    is_execution_artifact = e.source in ("shimcache", "amcache", "userassist")
    return (is_process or is_execution_artifact) and _in_user_writable_dir(e.path)


RULES: tuple[Rule, ...] = (
    Rule(
        "DT-001",
        "Event log cleared",
        "T1070.001",
        "Indicator Removal: Clear Windows Event Logs",
        "Defense Evasion",
        "high",
        "Rarely benign outside lab rebuilds. Check who cleared it and what happened just before.",
        _log_cleared,
    ),
    Rule(
        "DT-002",
        "Pass-the-hash style logon (type 9, seclogo)",
        "T1550.002",
        "Use Alternate Authentication Material: Pass the Hash",
        "Lateral Movement",
        "high",
        "Also produced by legitimate 'runas /netonly'. Check the process that requested the logon.",
        _pass_the_hash_logon,
    ),
    Rule(
        "DT-003",
        "Process accessed LSASS memory",
        "T1003.001",
        "OS Credential Dumping: LSASS Memory",
        "Credential Access",
        "high",
        "EDR/AV agents touch LSASS routinely. An unknown SourceImage is the red flag.",
        _lsass_access,
    ),
    Rule(
        "DT-004",
        "Encoded PowerShell command line",
        "T1059.001",
        "Command and Scripting Interpreter: PowerShell",
        "Execution",
        "high",
        "Some management tools use -EncodedCommand. Decode the Base64 (UTF-16LE) and read it.",
        _encoded_powershell,
    ),
    Rule(
        "DT-005",
        "Service launches a shell, script host or user-writable binary",
        "T1543.003",
        "Create or Modify System Process: Windows Service",
        "Persistence",
        "high",
        "Legitimate services almost always run a signed binary from Program Files or System32.",
        _suspicious_service_binary,
    ),
    Rule(
        "DT-006",
        "New service installed",
        "T1543.003",
        "Create or Modify System Process: Windows Service",
        "Persistence",
        "medium",
        "Software installs and updates create services. Correlate with installer activity.",
        _service_installed,
    ),
    Rule(
        "DT-007",
        "Scheduled task created",
        "T1053.005",
        "Scheduled Task/Job: Scheduled Task",
        "Persistence",
        "medium",
        "Updaters create tasks constantly. Look at the task's action and author.",
        _scheduled_task_created,
    ),
    Rule(
        "DT-008",
        "Local account created",
        "T1136.001",
        "Create Account: Local Account",
        "Persistence",
        "medium",
        "Expected during provisioning. Unexpected outside change windows.",
        _account_created,
    ),
    Rule(
        "DT-009",
        "Account added to a security group",
        "T1098",
        "Account Manipulation",
        "Persistence",
        "medium",
        "Treat additions to Administrators / Domain Admins as high priority.",
        _added_to_group,
    ),
    Rule(
        "DT-010",
        "Program executed from a user-writable folder",
        "T1204.002",
        "User Execution: Malicious File",
        "Execution",
        "medium",
        "Installers run from Temp/Downloads. Shimcache proves the file existed, not that it ran.",
        _execution_from_user_writable_dir,
    ),
    Rule(
        "DT-011",
        "Registry Run key autostart entry",
        "T1547.001",
        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "Persistence",
        "low",
        "Most Run entries are legitimate software. Review unfamiliar names and paths.",
        _run_key,
    ),
)


def run_rules(events: Iterable[TimelineEvent], rules: Iterable[Rule] = RULES) -> list[Finding]:
    """Return every (rule, event) match, most severe first, then by time."""
    rules = tuple(rules)
    findings = [Finding(rule, event) for event in events for rule in rules if rule.match(event)]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.rule.severity], sort_key(f.event)))
    return findings
