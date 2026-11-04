# Validation results: real Windows 11 artifacts

dfir-triage checked against artifacts from a disposable lab VM, using ground truth recorded
inside the VM (the real files' SHA-1s and modified times, and which rules each step should
trigger). Produced with the automation in [`lab/`](../lab/README.md); the manual procedure is
[lab-validation.md](lab-validation.md).

The hives and event logs are **not** committed: they contain the lab VM's identifiers.

## Setup

| | |
|---|---|
| Date | 2026-11-04 |
| Guest | Windows 11 Pro 26H2, build 26300.9457 (unactivated lab VM, built unattended) |
| Hypervisor | VirtualBox 7.2.14 on a Windows 11 host |
| dfir-triage | 0.2.0 plus the lab-automation changes released in 1.0.0, Python 3.11.9 |
| Logging | Process creation with command lines, account and group management, Other Object Access (scheduled tasks) |
| Not installed | Sysmon (so Sysmon-based detections were not exercised) |

## Result

Final run `20261104-120132`: **18 passed, 0 failed, 3 warnings.** 6 of 6 artifacts parsed,
4,469 timeline events.

| Check | Result | Detail |
|---|---|---|
| Artifacts parsed (Security/System EVTX, SYSTEM, SOFTWARE, NTUSER.DAT, Amcache) | PASS | 3,310 EVTX events, 770 SYSTEM, 7 NTUSER, 380 Amcache |
| Rules DT-001, DT-004, DT-005, DT-006, DT-007, DT-008, DT-009, DT-010, DT-011 | PASS | each fired on events from the lab activity itself, not on earlier Windows Setup events |
| Shimcache: `stage.exe` present | PASS | position 33 of 87 entries |
| Shimcache: timestamp equals the file's real last-modified time | PASS | parsed `2026-09-13 18:24:07.490355`, real `18:24:07.4903556` (same to the microsecond; the extra digit is below the parser's precision) |
| Run key `LabUpdater` | PASS | `C:\Users\Public\stage.exe` |
| Service `LabSvc` | PASS | `cmd.exe /c echo lab` |
| Amcache: `stage.exe` / `setup.exe` present | WARN | Windows had not inventoried the two test files by collection time |
| UserAssist: Explorer launch of `setup.exe` | WARN | not recorded when started from a scripted session |

### Amcache SHA-1, checked separately

Because the test files were not inventoried, the Amcache SHA-1 parsing was checked against eight
system files that Amcache did list. Each file was hashed inside the VM and compared with the
SHA-1 in dfir-triage's `timeline.csv`:

| File | SHA-1 (real file in the VM) | Match |
|---|---|---|
| cmd.exe | `d1682ea6d9ece5c98560048d22f1af6960ead9a9` | yes |
| conhost.exe | `24cf1b23c40c5635d473dc5408d13051c7a6f59c` | yes |
| auditpol.exe | `81b7e88e23f921c1c31c738f2a37f639bf8b8037` | yes |
| ctfmon.exe | `093f480c5f502fd598a96c2c32dca09aea636e5e` | yes |
| dwm.exe | `f6e9cc66a9847579bf92497a0e8b1e4795f70e14` | yes |
| explorer.exe | `3dd0bd41a79b3875aaca1a0cd2d34c3267a16740` | yes |
| lsass.exe | `258a9984be57a5000517fd76abff440f5562a315` | yes |
| dllhost.exe | `fbe14a54ef45d11d4131e5ef4caaf2d70dfee8e7` | yes |

**8 of 8 match.** These are public Microsoft binaries of this Windows build.

## What the lab runs found

The first runs did not pass. Every problem is listed here, including the ones in the test
harness itself.

**In dfir-triage**

- **Amcache entries had no path.** On this build each `InventoryApplicationFile` entry holds only
  `ProgramId` and `FileId`, with no `LowerCaseLongPath`, `Name` or `Size`. All 380 events had an
  empty path. The parser now takes the file name from the subkey name (`name_from_key`, which
  Windows cuts at 16 characters, e.g. `aggregatorhost.e`) and says that no path was recorded.
  Unit tests built from fake keys could not have caught this.

**In the lab harness**

- The guest received the program path twice (VirtualBox 7.2 already supplies `argv[0]`), so
  `shutdown /r` only printed its help. With no clean shutdown, Windows never wrote Shimcache and
  the first run failed the Shimcache check. The reboot is now verified by the guest's boot time.
- `net user` asks a Y/N question for passwords over 14 characters; run from a script it answers
  "N", so the test account was never created.
- That bug was hidden by a weak check: DT-008 and DT-009 "passed" on accounts that Windows Setup
  created hours earlier. The comparison now counts only findings from the lab activity window.
- Copies into existing guest folders failed with VirtualBox 7.2 (a trailing `\` is required).
- When the host slept or the VM was saved and resumed, the guest stopped answering Guest
  Additions commands. The runs now keep the host awake.

## Noise worth knowing about

Counts for the whole collection, which includes Windows Setup and Guest Additions installation:

| Rule | Findings | Note |
|---|---|---|
| DT-006 New service installed | 14 | mostly legitimate installs (Defender, Edge updater, VirtualBox drivers). An allowlist of signed system paths is a candidate for v1.1. |
| DT-009 Account added to a security group | 9 | Windows Setup adds built-in accounts to groups |
| DT-010 Program run from a user-writable folder | 5 | all from the lab activity (4688 and Shimcache) |
| DT-011 Run key autostart | 4 | 3 benign (`SecurityHealth`, `VBoxTray`, `OneDrive`) and the planted `LabUpdater` |
| DT-008 Local account created | 3 | 2 from Windows Setup, 1 lab |

Also seen: the host name is `labws01` in event logs and `LABWS01` in registry events.

## Not covered by this validation

- DT-002 (pass-the-hash) and DT-003 (LSASS access): they need attacker activity, which this
  harmless script does not create.
- Sysmon-based detections: Sysmon was not installed in this run.
- UserAssist on real data (see the warning above), and Amcache entries that do include a path
  (other Windows builds).
- Comparison with Eric Zimmerman's AppCompatCacheParser and AmcacheParser: supported by
  `run_validation.ps1 -EzToolsDir`, not run here.
