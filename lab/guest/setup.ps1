# Runs ONCE inside the lab VM, before the "clean" snapshot.
# Turns on the logging that dfir-triage's rules read.
$ErrorActionPreference = "Stop"

auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable    # 4698 scheduled tasks
auditpol /set /subcategory:"User Account Management" /success:enable       # 4720
auditpol /set /subcategory:"Security Group Management" /success:enable     # 4732
auditpol /set /subcategory:"Logon" /success:enable /failure:enable         # 4624 / 4625
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
wevtutil sl Security /ms:209715200    # 200 MB so nothing rolls over during a run
wevtutil sl System /ms:52428800

# Optional Sysmon (only if the host copied it in).
$sysmon = "C:\lab\tools\Sysmon64.exe"
if (Test-Path $sysmon) {
    & $sysmon -accepteula -i "C:\lab\tools\sysmonconfig.xml" | Out-Null
    Write-Output "Sysmon installed"
}

Write-Output "Lab setup complete on $env:COMPUTERNAME"
