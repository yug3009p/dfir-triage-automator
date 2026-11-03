# Runs inside the lab VM after the post-activity reboot (Shimcache is only written to the
# SYSTEM hive at shutdown). Collects the artifacts dfir-triage parses into C:\evidence.
$ErrorActionPreference = "Stop"
$e = "C:\evidence"
Remove-Item $e -Recurse -Force -ErrorAction SilentlyContinue
$userDir = Join-Path $e "Users\$env:USERNAME"
New-Item -ItemType Directory -Force $userDir | Out-Null

reg save HKLM\SYSTEM "$e\SYSTEM" /y | Out-Null
reg save HKLM\SOFTWARE "$e\SOFTWARE" /y | Out-Null
reg save HKCU "$userDir\NTUSER.DAT" /y | Out-Null
# Amcache.hve is locked while Windows runs; esentutl copies it through a shadow copy.
esentutl.exe /y C:\Windows\AppCompat\Programs\Amcache.hve /vss /d "$e\Amcache.hve" | Out-Null

wevtutil epl Security "$e\Security.evtx"
wevtutil epl System "$e\System.evtx"
if (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue) {
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" "$e\Sysmon.evtx"
}
Copy-Item C:\lab\ground-truth.json $e

Get-ChildItem $e -Recurse -File | ForEach-Object { "{0,10:N0}  {1}" -f $_.Length, $_.FullName.Substring($e.Length + 1) }
