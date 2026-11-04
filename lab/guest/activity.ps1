# Runs inside the lab VM on each validation run. Generates known, HARMLESS activity using
# only built-in Windows programs, and records ground truth (paths, hashes, times) in
# C:\lab\ground-truth.json so the host can check the parsers against reality.
$ErrorActionPreference = "Stop"
$truth = [ordered]@{ started_utc = (Get-Date).ToUniversalTime().ToString("o"); hostname = $env:COMPUTERNAME; user = $env:USERNAME; steps = @() }

function Step([string] $Name, [string[]] $ExpectedRules, [hashtable] $Data = @{}) {
    $script:truth.steps += [ordered]@{ name = $Name; time_utc = (Get-Date).ToUniversalTime().ToString("o"); expected_rules = $ExpectedRules; data = $Data }
}

function FileFacts([string] $Path) {
    $item = Get-Item $Path
    return @{
        path = $item.FullName
        sha1 = (Get-FileHash $Path -Algorithm SHA1).Hash.ToLower()
        sha256 = (Get-FileHash $Path -Algorithm SHA256).Hash.ToLower()
        last_write_utc = $item.LastWriteTimeUtc.ToString("o")
    }
}

# 1. Programs in user-writable folders: Shimcache, Amcache, 4688 (DT-010).
#    notepad.exe copies; the copy keeps notepad's last-modified time, which Shimcache records.
$stage = "C:\Users\Public\stage.exe"
$setup = Join-Path $env:USERPROFILE "Downloads\setup.exe"
Copy-Item C:\Windows\System32\notepad.exe $stage -Force
Copy-Item C:\Windows\System32\notepad.exe $setup -Force
$p = Start-Process $stage -PassThru; Start-Sleep -Seconds 3; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Step "run_from_public" @("DT-010") @{ stage = (FileFacts $stage); setup = (FileFacts $setup) }

# 2. Launch through the Explorer shell so UserAssist records it (best effort: needs the
#    lab user's interactive session, which the unattended install logs in automatically).
Start-Process explorer.exe -ArgumentList "`"$setup`""; Start-Sleep -Seconds 5
Get-Process notepad, setup -ErrorAction SilentlyContinue | Stop-Process -Force
Step "explorer_launch" @() @{ path = $setup }

# 3. Run key persistence (DT-011).
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LabUpdater /t REG_SZ /d $stage /f | Out-Null
Step "run_key" @("DT-011") @{ value_name = "LabUpdater"; command = $stage }

# 4. Service that launches a shell (DT-005, DT-006). Never started.
sc.exe create LabSvc binPath= "cmd.exe /c echo lab" start= demand | Out-Null
Step "service" @("DT-005", "DT-006") @{ service = "LabSvc"; image_path = "cmd.exe /c echo lab" }

# 5. Scheduled task (DT-007).
schtasks /create /tn LabTask /tr notepad.exe /sc once /st 23:59 /f | Out-Null
Step "scheduled_task" @("DT-007") @{ task = "LabTask" }

# 6. Encoded PowerShell that only prints "lab" (DT-004).
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output lab'))
powershell.exe -NoProfile -EncodedCommand $b64 | Out-Null
Step "encoded_powershell" @("DT-004") @{ encoded = $b64 }

# 7. Local account + admin group membership (DT-008, DT-009). Random password, account disabled.
# Not "net user": for passwords over 14 characters it asks a Y/N question, which a script
# answers "N", so the account was silently never created.
$pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ }) + "!a1"
New-LocalUser -Name labuser -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -Disabled -Description "dfir-triage lab test account" | Out-Null
Add-LocalGroupMember -Group Administrators -Member labuser
if (-not (Get-LocalGroupMember -Group Administrators -Member labuser -ErrorAction SilentlyContinue)) { throw "labuser was not added to Administrators" }
Step "account_and_group" @("DT-008", "DT-009") @{ account = "labuser" }

# 8. Clear a non-security log (System 104, DT-001).
wevtutil cl Application
Step "clear_application_log" @("DT-001") @{ log = "Application" }

# 9. Ask Windows to refresh Amcache now rather than on its own schedule.
schtasks /run /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Start-Sleep -Seconds 120
Step "amcache_refresh" @()

$truth.finished_utc = (Get-Date).ToUniversalTime().ToString("o")
$truth | ConvertTo-Json -Depth 6 | Set-Content C:\lab\ground-truth.json -Encoding utf8
Write-Output "Activity complete: $($truth.steps.Count) steps"
