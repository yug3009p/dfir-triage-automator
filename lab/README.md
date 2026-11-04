# Automated lab validation

Checks dfir-triage against **real** Windows artifacts from a disposable VirtualBox VM, with no
clicks. The manual equivalent is [docs/lab-validation.md](../docs/lab-validation.md).

## What you need

- VirtualBox 7.x (with the Extension Pack) on a Windows host. Windows 11 Home is fine.
- A Windows 11 x64 ISO from Microsoft (the Evaluation Center ISO or the retail ISO from
  microsoft.com/software-download/windows11; the lab VM can run unactivated).
- About 70 GB free disk and 4 GB of RAM for the VM while it runs.
- Optional: Sysmon (`Sysmon64.exe` + a config such as SwiftOnSecurity's `sysmonconfig.xml`) for
  the Sysmon-based rules, and Eric Zimmerman's `AppCompatCacheParser.exe` / `AmcacheParser.exe`
  for a second, independent comparison.

## Run it

```powershell
# Once: build the VM (30-60 min, unattended) and save a "clean" snapshot
.\lab\build_vm.ps1 -IsoPath C:\ISOs\Win11_x64.iso [-SysmonDir C:\Tools\Sysmon]

# Every validation run (~15 min): restore snapshot, generate activity, collect, check
.\lab\run_validation.ps1 [-EzToolsDir C:\Tools\EZ]
```

Each run writes `lab-runs\<timestamp>\` with the collected evidence, dfir-triage's output, and
`validation-results.md`. The command exits non-zero if any check fails. `lab-runs\` and the
generated lab password (`lab\.secrets\`) are git-ignored.

## What gets checked

`guest\activity.ps1` runs harmless, built-in Windows commands (a notepad copy run from
`C:\Users\Public`, a Run key, a service that would run `cmd /c echo lab`, a scheduled task,
encoded PowerShell that prints "lab", a disabled local account added to Administrators, and a
cleared Application log). It records **ground truth** inside the VM: each planted file's real
SHA-1 and last-modified time, and which rules each step should trigger.

`compare.py` then checks, without relying on any other tool:

| Check | Pass condition |
|---|---|
| Artifact coverage | Every hive and event log parsed without error |
| Rules | DT-001, DT-004, DT-005, DT-006, DT-007, DT-008, DT-009, DT-010, DT-011 fire |
| Shimcache | `stage.exe` present, timestamp equals the file's real last-modified time |
| Amcache | SHA-1 equals the real file's SHA-1 (absence is only a warning: Windows decides when to inventory) |
| Run key / Service | `LabUpdater` and `LabSvc` parsed with the exact command lines |
| UserAssist | Explorer launch recorded (warning only: may not register from a scripted session) |
| Eric Zimmerman's tools (optional) | Same Shimcache entries and timestamps, same Amcache SHA-1 set |

DT-002 (pass-the-hash) and DT-003 (LSASS access) need attacker activity and are not exercised by
this harmless script.

## Safety

- The VM is a throwaway lab machine on NAT plus an isolated host-only network. Never put personal
  data in it. UAC is turned off inside it so the scripts run with admin rights.
- Activity uses only built-in Windows programs; nothing is executed from the internet.
- Collected evidence contains the VM's identifiers and stays on your machine.

## Status

Run end to end on 2026-11-04 against Windows 11 Pro 26H2 (build 26300) with VirtualBox 7.2.14:
18 passed, 0 failed, 3 warnings. See [docs/validation-results.md](../docs/validation-results.md),
including the bugs the first runs found.

Keep the host awake while it runs: if Windows sleeps or VirtualBox saves the VM mid-run, the
guest stops answering Guest Additions commands. Restart the VM (or restore `clean`) to recover.
