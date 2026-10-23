# Rollback: restore the original (SYSTEM) tasks from the installer's backup, remove the ACEs and disable the
# service accounts. Run elevated on the gateway host. Settings: asg-windows.psd1 (same file the installer used).
param([string]$Src = $PSScriptRoot)
$ErrorActionPreference = 'Continue'
. (Join-Path $Src '_site.ps1'); $S = Get-AsgSite $Src
$bak = "C:\ProgramData\asg\$($S.BackupTag)"; $home0 = $S.StateHome; $state = "$home0\.agent-security-gateway"
foreach ($t in $S.GatewayTask, $S.TunnelTask) {
  Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
  Register-ScheduledTask -TaskName $t -Xml (Get-Content "$bak\$t.xml" -Raw) | Out-Null
}
icacls 'C:\ProgramData\asg-tunnel\id_ed25519' /setowner Administrators | Out-Null
foreach ($p in $home0, $S.CodeDir, $state) {
  icacls $p /remove:g $S.GatewayAccount /c | Out-Null; icacls $p /remove:g $S.GatewayAccount /t /c /q | Out-Null
}
icacls 'C:\ProgramData\asg-tunnel' /remove:g $S.TunnelAccount /t /c /q | Out-Null
if (Test-Path "$state\asg-tunnel.ps1") { icacls "$state\asg-tunnel.ps1" /reset | Out-Null }
foreach ($u in $S.GatewayAccount, $S.TunnelAccount) { Disable-LocalUser -Name $u -ErrorAction SilentlyContinue }
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "gateway.py|inspector_relay|asg-tunnel|:127.0.0.1:$($S.AsgPort)" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-ScheduledTask $S.GatewayTask; Start-ScheduledTask $S.TunnelTask
"rolled back"
