<#
.SYNOPSIS
    Build the disposable Windows 11 lab VM used to validate dfir-triage (VirtualBox, unattended).

.DESCRIPTION
    Creates the VM (EFI, TPM 2.0, Secure Boot), installs Windows 11 from the ISO without
    any clicks, installs Guest Additions, applies lab settings (audit policy, command-line
    logging, UAC off), and saves a snapshot called "clean". Every validation run starts
    from that snapshot. Takes 30-60 minutes, mostly waiting for Windows Setup.

    This VM is a throwaway lab machine. Never put personal data in it.

.EXAMPLE
    .\lab\build_vm.ps1 -IsoPath C:\ISOs\Win11_English_x64.iso
#>
param(
    [string] $IsoPath = "",
    [string] $VmName = "DFIR-Win11",
    [int] $ImageIndex = 0,            # 0 = pick "Windows 11 Pro" (or Enterprise) automatically
    [int] $MemoryMB = 4096,
    [int] $Cpus = 2,
    [int] $DiskGB = 64,
    [string] $SysmonDir = "",         # optional folder containing Sysmon64.exe and sysmonconfig.xml
    [switch] $Resume                  # continue an interrupted build of an existing VM
)

. "$PSScriptRoot\common.ps1"

if ($Resume) {
    # The host session ended mid-build and VirtualBox saved the VM: start it again and carry on.
    if (-not (Test-VmExists $VmName)) { throw "No VM named $VmName to resume." }
    if ((Get-VmState $VmName) -ne "running") { Invoke-VBox startvm $VmName --type headless | Out-Null }
    Write-Host "Resumed $VmName. Waiting for Windows Setup to finish (up to 90 minutes)..."
} else {
if (-not (Test-Path $IsoPath)) { throw "ISO not found: $IsoPath" }
if (Test-VmExists $VmName) { throw "A VM named $VmName already exists. Use -Resume to continue it, or delete it in VirtualBox." }

# 1. Pick the Windows edition inside the ISO.
if ($ImageIndex -eq 0) {
    $detect = (Invoke-Native -Exe $script:VBox -Arguments @("unattended", "detect", "--iso=$IsoPath")).Output
    $match = [regex]::Matches($detect, '(?m)^\s*Image\s*#?\s*(\d+)\s*[:=]\s*(.*)$') |
        # Exact edition name followed by the version in brackets, e.g. "Windows 11 Pro (10.0.26300...".
        # This skips "Pro N", "Pro Education" and "Pro for Workstations".
        Where-Object { $_.Groups[2].Value -cmatch '^Windows 11 (Pro|Enterprise) \(' } |
        Select-Object -First 1
    if (-not $match) { throw "Could not pick a Windows 11 Pro/Enterprise image automatically. Detection output:`n$detect`nRe-run with -ImageIndex <n>." }
    $ImageIndex = [int]$match.Groups[1].Value
    Write-Host "Using image $ImageIndex : $($match.Groups[2].Value.Trim())"
}

# 2. Create the VM with what Windows 11 Setup requires.
$machineFolder = ((Invoke-VBox list systemproperties) -split "`n" | Select-String "Default machine folder") -replace '.*:\s+', ''
$vmDir = Join-Path $machineFolder.Trim() $VmName
Invoke-VBox createvm --name $VmName --ostype Windows11_64 --register | Out-Null
Invoke-VBox modifyvm $VmName --memory $MemoryMB --cpus $Cpus --firmware efi --tpm-type 2.0 `
    --graphicscontroller vboxsvga --vram 128 --clipboard-mode disabled --drag-and-drop disabled `
    --nic1 nat --nic2 hostonly --host-only-adapter2 "VirtualBox Host-Only Ethernet Adapter" | Out-Null
Invoke-VBox modifynvram $VmName inituefivarstore | Out-Null
Invoke-VBox modifynvram $VmName enrollmssignatures | Out-Null
Invoke-VBox modifynvram $VmName enrollorclpk | Out-Null
Invoke-VBox createmedium disk --filename (Join-Path $vmDir "$VmName.vdi") --size ($DiskGB * 1024) | Out-Null
Invoke-VBox storagectl $VmName --name SATA --add sata --controller IntelAhci | Out-Null
Invoke-VBox storageattach $VmName --storagectl SATA --port 0 --device 0 --type hdd --medium (Join-Path $vmDir "$VmName.vdi") | Out-Null

# 3. Unattended install. The post-install command runs as SYSTEM at the end of Setup:
#    UAC off so lab scripts run with full admin rights (lab VM only), no sleep.
$postInstall = 'cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f' +
    ' & reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f' +
    ' & powercfg /change standby-timeout-ac 0 & powercfg /change monitor-timeout-ac 0'
$passwordFile = Join-Path $script:SecretsDir "lab-password.txt"
Get-LabPassword | Out-Null
Invoke-VBox unattended install $VmName --iso=$IsoPath --image-index=$ImageIndex `
    --user=$script:GuestUser --user-password-file=$passwordFile --full-user-name="Lab User" `
    --hostname="labws01.lab.local" --locale=en_US --country=US --time-zone=UTC `
    --install-additions --post-install-command=$postInstall --start-vm=headless | Out-Null
Write-Host "Windows Setup is running headless. Waiting for the guest (up to 90 minutes)..."
}
Wait-GuestReady -VmName $VmName -TimeoutMinutes 90
Restart-Guest -VmName $VmName   # apply the UAC change

# 4. One-time lab configuration (audit policy, command-line logging, optional Sysmon).
Copy-ToGuest -VmName $VmName -HostPath (Join-Path $PSScriptRoot "guest\setup.ps1") -GuestDir "C:\lab"
if ($SysmonDir) {
    foreach ($f in "Sysmon64.exe", "sysmonconfig.xml") { Copy-ToGuest -VmName $VmName -HostPath (Join-Path $SysmonDir $f) -GuestDir "C:\lab\tools" }
}
Invoke-GuestScript -VmName $VmName -GuestPath "C:\lab\setup.ps1" | Write-Host

# 5. Snapshot the clean state. Every validation run restores it.
Stop-Vm -VmName $VmName
foreach ($port in 1..3) {  # eject install media; the port VirtualBox used is not fixed
    try { Invoke-VBox storageattach $VmName --storagectl SATA --port $port --device 0 --type dvddrive --medium emptydrive | Out-Null } catch { }
}
Invoke-VBox snapshot $VmName take clean --description "Fresh lab install, before any test activity" | Out-Null
Write-Host "Done. VM $VmName is ready with snapshot 'clean'. Next: .\lab\run_validation.ps1"
