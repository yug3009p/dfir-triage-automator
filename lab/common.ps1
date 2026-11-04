# Shared helpers for the VirtualBox lab scripts. Dot-source this file.

$ErrorActionPreference = "Stop"
$script:VBox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$script:LabRoot = $PSScriptRoot
$script:SecretsDir = Join-Path $PSScriptRoot ".secrets"   # git-ignored
$script:GuestUser = "lab"
$script:GuestPowerShell = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

function Invoke-Native {
    # Windows PowerShell 5.1 turns any stderr line from a native program into a terminating
    # error when ErrorActionPreference is Stop. VBoxManage prints progress to stderr, so relax
    # it for the call and judge success by the exit code instead.
    param([string] $Exe, [string[]] $Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $output = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } }
    finally { $ErrorActionPreference = $previous }
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join "`n") }
}

function Invoke-VBox {
    # Run VBoxManage and fail loudly on a non-zero exit code. A simple (non-advanced) function,
    # so options such as --name reach VBoxManage instead of being parsed by PowerShell.
    $result = Invoke-Native -Exe $script:VBox -Arguments $args
    if ($result.ExitCode -ne 0) {
        # Never echo the guest password into logs.
        $shown = ($args -join ' ') -replace '(--password\s+)\S+', '$1***'
        throw "VBoxManage $shown failed:`n$($result.Output)"
    }
    return $result.Output
}

function Get-LabPassword {
    # One random password per lab, stored only on this machine.
    $file = Join-Path $script:SecretsDir "lab-password.txt"
    if (-not (Test-Path $file)) {
        New-Item -ItemType Directory -Force $script:SecretsDir | Out-Null
        $chars = [char[]]"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
        $password = -join (1..20 | ForEach-Object { $chars | Get-Random })
        Set-Content -Path $file -Value $password -NoNewline -Encoding ascii
    }
    return (Get-Content $file -Raw).Trim()
}

function Test-VmExists([string] $VmName) {
    return [bool]((Invoke-VBox list vms) -split "`n" -match "^`"$([regex]::Escape($VmName))`"")
}

function Get-VmState([string] $VmName) {
    $line = (Invoke-VBox showvminfo $VmName --machinereadable) -split "`n" | Where-Object { $_ -like 'VMState=*' }
    return ($line -replace 'VMState="(.*)"', '$1')
}

function Invoke-Guest {
    # Run a program inside the guest and return its output. Throws on failure.
    param(
        [string] $VmName,
        [string] $Exe,
        [string[]] $Arguments = @(),
        [int] $TimeoutSeconds = 600
    )
    $password = Get-LabPassword
    $vboxArgs = @("guestcontrol", $VmName, "--username", $script:GuestUser, "--password", $password,
        "run", "--exe", $Exe, "--timeout", [string]($TimeoutSeconds * 1000), "--wait-stdout", "--wait-stderr", "--") + $Arguments
    # VBoxManage 7.2 supplies argv[0] from --exe itself; repeating $Exe after "--" makes it the
    # first real argument (shutdown.exe then prints its help instead of rebooting).
    $result = Invoke-Native -Exe $script:VBox -Arguments $vboxArgs
    if ($result.ExitCode -ne 0) { throw "Guest command failed ($Exe $($Arguments -join ' ')):`n$($result.Output)" }
    return $result.Output
}

function Invoke-GuestScript([string] $VmName, [string] $GuestPath, [int] $TimeoutSeconds = 900) {
    Invoke-Guest -VmName $VmName -Exe $script:GuestPowerShell -TimeoutSeconds $TimeoutSeconds `
        -Arguments @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $GuestPath)
}

function Wait-GuestReady([string] $VmName, [int] $TimeoutMinutes = 30) {
    # Guest Additions report a version before the user session is usable, so also try a real command.
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ((Get-Date) -lt $deadline) {
        try {
            $out = Invoke-Guest -VmName $VmName -Exe "C:\Windows\System32\cmd.exe" -Arguments @("/c", "echo", "ready") -TimeoutSeconds 30
            if ($out -match "ready") { return }
        } catch { }
        Start-Sleep -Seconds 20
    }
    throw "Guest $VmName did not become ready within $TimeoutMinutes minutes."
}

function Copy-ToGuest([string] $VmName, [string] $HostPath, [string] $GuestDir) {
    $password = Get-LabPassword
    Invoke-VBox guestcontrol $VmName --username $script:GuestUser --password $password mkdir --parents $GuestDir | Out-Null
    Invoke-VBox guestcontrol $VmName --username $script:GuestUser --password $password `
        copyto --target-directory ($GuestDir.TrimEnd('\') + '\') $HostPath | Out-Null  # trailing \ = "into this existing folder" (VBox 7.x)
}

function Copy-FromGuest([string] $VmName, [string] $GuestDir, [string] $HostDir) {
    $password = Get-LabPassword
    New-Item -ItemType Directory -Force $HostDir | Out-Null
    Invoke-VBox guestcontrol $VmName --username $script:GuestUser --password $password `
        copyfrom --recursive --target-directory ($HostDir.TrimEnd('\') + '\') $GuestDir | Out-Null
}

function Get-GuestBootTime([string] $VmName) {
    $out = Invoke-Guest -VmName $VmName -Exe $script:GuestPowerShell -TimeoutSeconds 60 -Arguments @("-NoProfile", "-Command",
        "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')")
    return $out.Trim()
}

function Restart-Guest([string] $VmName) {
    # A clean restart matters: Windows writes Shimcache to the SYSTEM hive only at a clean shutdown.
    $before = Get-GuestBootTime $VmName
    Invoke-Guest -VmName $VmName -Exe "C:\Windows\System32\shutdown.exe" -Arguments @("/r", "/t", "5") -TimeoutSeconds 30 | Out-Null
    Start-Sleep -Seconds 60  # let it go down before polling again
    Wait-GuestReady -VmName $VmName
    $after = Get-GuestBootTime $VmName
    if ($after -eq $before) { throw "Guest $VmName did not restart (boot time still $before)." }
}

function Stop-Vm([string] $VmName, [int] $TimeoutMinutes = 5) {
    if ((Get-VmState $VmName) -ne "running") { return }
    Invoke-VBox controlvm $VmName acpipowerbutton | Out-Null
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ((Get-Date) -lt $deadline -and (Get-VmState $VmName) -ne "poweroff") { Start-Sleep -Seconds 5 }
    if ((Get-VmState $VmName) -ne "poweroff") { Invoke-VBox controlvm $VmName poweroff | Out-Null }
}
