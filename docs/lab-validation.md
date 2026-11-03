# Lab validation: real registry hives

The Shimcache, Amcache and registry parsers are unit-tested against fake keys and hand-built
binary data. This guide checks them against **real hives** from a lab VM, using Eric Zimmerman's
tools as the reference. Plan on about 3 hours.

Record the results, including any mismatches, in `docs/validation-results.md`. A mismatch is
useful information: write it down rather than quietly fixing it away.

## 1. Build the lab

- A **disposable** Windows 11 VM. The free Windows 11 Enterprise evaluation from the Microsoft
  Evaluation Center works. Hyper-V, VirtualBox or VMware are all fine.
- Never use your own computer or any machine with personal, employer or client data. Hives
  contain usernames, hostnames and activity history.
- Install [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) with a public
  config such as SwiftOnSecurity's `sysmon-config`.
- Take a snapshot so you can repeat the run.

In an **elevated PowerShell** inside the VM, turn on the logging the rules need:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable   # 4698 scheduled tasks
auditpol /set /subcategory:"User Account Management" /success:enable      # 4720
auditpol /set /subcategory:"Security Group Management" /success:enable    # 4732
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

## 2. Generate known, harmless activity

Every step uses built-in Windows binaries and maps to an artifact and a rule. Note the time
before you start.

```powershell
# Program in user-writable folders -> Shimcache, Amcache, Sysmon 1 / 4688 (DT-010)
Copy-Item C:\Windows\System32\notepad.exe C:\Users\Public\stage.exe
Copy-Item C:\Windows\System32\notepad.exe "$env:USERPROFILE\Downloads\setup.exe"
Start-Process C:\Users\Public\stage.exe; Start-Sleep 2; Stop-Process -Name stage

# Run key -> NTUSER.DAT (DT-011)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LabUpdater /t REG_SZ /d C:\Users\Public\stage.exe /f

# Service that launches a shell -> 7045 + SYSTEM\Services (DT-005, DT-006)
sc.exe create LabSvc binPath= "cmd.exe /c echo lab" start= demand

# Scheduled task -> 4698 (DT-007)
schtasks /create /tn LabTask /tr notepad.exe /sc once /st 23:59 /f

# Encoded PowerShell that only prints "lab" -> 4688 / Sysmon 1 (DT-004)
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output lab'))
powershell -NoProfile -EncodedCommand $b64

# Local account + group change -> 4720, 4732 (DT-008, DT-009)
net user labuser "Lab-Only-Passw0rd!" /add
net localgroup Administrators labuser /add

# Clear a non-security log -> System 104 (DT-001)
wevtutil cl Application
```

Then, using the mouse, open `Downloads` in Explorer and double-click `setup.exe` (this creates a
UserAssist entry), and close it.

Two artifacts are only written later, so finish with:

```powershell
# Amcache is refreshed by this scheduled task (it can take a few minutes)
schtasks /run /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
# Shimcache is written to the SYSTEM hive at shutdown, so reboot before collecting
Restart-Computer
```

## 3. Collect

After the reboot, in an elevated PowerShell:

```powershell
$e = "C:\evidence"
New-Item -ItemType Directory -Force "$e\Users\$env:USERNAME" | Out-Null
reg save HKLM\SYSTEM   "$e\SYSTEM"   /y
reg save HKLM\SOFTWARE "$e\SOFTWARE" /y
reg save HKCU          "$e\Users\$env:USERNAME\NTUSER.DAT" /y
esentutl.exe /y C:\Windows\AppCompat\Programs\Amcache.hve /vss /d "$e\Amcache.hve"
wevtutil epl Security "$e\Security.evtx"
wevtutil epl System   "$e\System.evtx"
wevtutil epl Microsoft-Windows-Sysmon/Operational "$e\Sysmon.evtx"
```

[KAPE](https://www.kroll.com/en/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape)
with the `RegistryHives`, `Amcache` and `EventLogs` targets is an alternative to these commands.

## 4. Run both tools

```powershell
dfir-triage C:\evidence -o C:\out\dfir-triage

# Eric Zimmerman's tools (https://ericzimmerman.github.io)
AppCompatCacheParser.exe -f C:\evidence\SYSTEM --csv C:\out\ez
AmcacheParser.exe -f C:\evidence\Amcache.hve --csv C:\out\ez
RECmd.exe -d C:\evidence --bn BatchExamples\Kroll_Batch.reb --csv C:\out\ez
```

## 5. Compare

| Artifact | Check | Reference |
|---|---|---|
| Shimcache | Same number of entries, same order (`cache_position`), same paths, same timestamps | AppCompatCacheParser |
| Amcache | `stage.exe` / `setup.exe` present with the same SHA-1 and key timestamp | AmcacheParser |
| Run keys | `LabUpdater` value and command | RECmd |
| Services | `LabSvc` with `ImagePath = cmd.exe /c echo lab` | RECmd |
| UserAssist | `setup.exe` with a run count of at least 1 and a matching last-run time | RECmd |

Expected `dfir-triage` findings: DT-001, DT-004, DT-005, DT-006, DT-007, DT-008, DT-009,
DT-010 and DT-011. DT-002 and DT-003 need pass-the-hash or LSASS-access activity, which this
harmless script does not create.

## 6. What to commit

Commit `docs/validation-results.md` with tool versions, the counts per artifact, and any
differences found. **Do not commit the hives or event logs**: even from a lab VM they contain
machine identifiers, and they are large. Small, reviewed CSV extracts are fine.
