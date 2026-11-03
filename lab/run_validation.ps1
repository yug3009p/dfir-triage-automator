<#
.SYNOPSIS
    One command: run known activity in the lab VM, collect the artifacts, run dfir-triage,
    and check the results against ground truth. About 15 minutes, no clicks.

.DESCRIPTION
    1. Restore the VM to its "clean" snapshot and start it headless.
    2. Run guest\activity.ps1 (harmless, built-in programs only; records ground truth).
    3. Reboot (Shimcache is written at shutdown), run guest\collect.ps1.
    4. Copy the evidence to lab-runs\<timestamp>\evidence and restore the snapshot.
    5. Run dfir-triage, and Eric Zimmerman's tools if -EzToolsDir is given.
    6. Run lab\compare.py, which writes validation-results.md and exits non-zero on failure.

    lab-runs\ is git-ignored: evidence holds VM identifiers and is never committed.

.EXAMPLE
    .\lab\run_validation.ps1
    .\lab\run_validation.ps1 -EzToolsDir C:\Tools\EZ
#>
param(
    [string] $VmName = "DFIR-Win11",
    [string] $EzToolsDir = "",       # folder with AppCompatCacheParser.exe, AmcacheParser.exe, RECmd\RECmd.exe
    [string] $Python = ""            # defaults to the repo's .venv
)

. "$PSScriptRoot\common.ps1"
$repo = Split-Path $PSScriptRoot -Parent
if (-not $Python) { $Python = Join-Path $repo ".venv\Scripts\python.exe" }
if (-not (Test-VmExists $VmName)) { throw "VM $VmName not found. Build it first: .\lab\build_vm.ps1 -IsoPath <iso>" }

$run = Join-Path $repo ("lab-runs\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Force $run | Out-Null
Write-Host "Run folder: $run"

try {
    Write-Host "[1/6] Restoring clean snapshot and starting the VM"
    Stop-Vm -VmName $VmName
    Invoke-VBox snapshot $VmName restore clean | Out-Null
    Invoke-VBox startvm $VmName --type headless | Out-Null
    Wait-GuestReady -VmName $VmName

    Write-Host "[2/6] Generating known activity"
    foreach ($f in "activity.ps1", "collect.ps1") { Copy-ToGuest -VmName $VmName -HostPath (Join-Path $PSScriptRoot "guest\$f") -GuestDir "C:\lab" }
    Invoke-GuestScript -VmName $VmName -GuestPath "C:\lab\activity.ps1" | Write-Host

    Write-Host "[3/6] Rebooting so Shimcache is flushed, then collecting"
    Restart-Guest -VmName $VmName
    Invoke-GuestScript -VmName $VmName -GuestPath "C:\lab\collect.ps1" | Write-Host

    Write-Host "[4/6] Copying evidence to the host"
    Copy-FromGuest -VmName $VmName -GuestDir "C:\evidence" -HostDir $run
}
finally {
    # Always leave the lab VM off and clean, even if a step failed.
    Stop-Vm -VmName $VmName
    try { Invoke-VBox snapshot $VmName restore clean | Out-Null } catch { Write-Warning "Could not restore snapshot: $_" }
}
$evidence = Join-Path $run "evidence"

Write-Host "[5/6] Running dfir-triage"
$triage = Invoke-Native -Exe $Python -Arguments @("-m", "dfir_triage", $evidence, "-o", (Join-Path $run "dfir-triage"), "-v")
Write-Host $triage.Output
if ($triage.ExitCode -ne 0) { throw "dfir-triage failed" }

if ($EzToolsDir) {
    $ez = Join-Path $run "ez"
    Invoke-Native -Exe (Join-Path $EzToolsDir "AppCompatCacheParser.exe") -Arguments @("-f", (Join-Path $evidence "SYSTEM"), "--csv", $ez, "--csvf", "shimcache.csv") | Out-Null
    Invoke-Native -Exe (Join-Path $EzToolsDir "AmcacheParser.exe") -Arguments @("-f", (Join-Path $evidence "Amcache.hve"), "--csv", $ez, "-i") | Out-Null
    Write-Host "Eric Zimmerman tool output: $ez"
}

Write-Host "[6/6] Comparing with ground truth"
$result = Invoke-Native -Exe $Python -Arguments @((Join-Path $PSScriptRoot "compare.py"), $run)
Write-Host $result.Output
exit $result.ExitCode
