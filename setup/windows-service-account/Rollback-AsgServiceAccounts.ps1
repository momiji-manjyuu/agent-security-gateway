# Rev19 rollback: restore the SYSTEM tasks, ACLs and disable the service accounts. Run elevated.
$ErrorActionPreference = 'Continue'
$bak = 'C:\ProgramData\asg\bak-r19'
foreach ($t in 'AgentSecurityGateway', 'ASG-Tunnel-90') {
  Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
  Register-ScheduledTask -TaskName $t -Xml (Get-Content "$bak\$t.xml" -Raw) | Out-Null
}
icacls 'C:\ProgramData\asg-tunnel\id_ed25519' /setowner Administrators | Out-Null
foreach ($p in 'C:\Users\User', 'C:\Users\User\agent-security-gateway', 'C:\Users\User\.agent-security-gateway') {
  icacls $p /remove:g asgsvc /c | Out-Null; icacls $p /remove:g asgsvc /t /c /q | Out-Null
}
icacls 'C:\ProgramData\asg-tunnel' /remove:g asgtun /t /c /q | Out-Null
icacls 'C:\Users\User\.agent-security-gateway\asg-tunnel.ps1' /reset | Out-Null
foreach ($u in 'asgsvc', 'asgtun') { Disable-LocalUser -Name $u -ErrorAction SilentlyContinue }
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'gateway.py|inspector_relay|asg-tunnel|8788:127.0.0.1:8788' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-ScheduledTask AgentSecurityGateway; Start-ScheduledTask ASG-Tunnel-90
"rolled back"
