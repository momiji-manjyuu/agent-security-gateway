# Rev19: move the ASG gateway and tunnel scheduled tasks from SYSTEM to dedicated low-privilege local accounts.
# Run elevated on the ASG host. Idempotent. Writes backups (*.bak-r19*) used by Rollback-AsgServiceAccounts.ps1.
# Passwords are random, never printed or stored; only Task Scheduler keeps them. Re-run to rotate.
param([string]$Src = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$home0 = 'C:\Users\User'
$state = "$home0\.agent-security-gateway"
$code  = "$home0\agent-security-gateway"
$bin   = 'C:\ProgramData\asg\bin'
$tun   = 'C:\ProgramData\asg-tunnel'
$bak   = 'C:\ProgramData\asg\bak-r19'
New-Item -ItemType Directory -Force $bin, $bak, "$tun\logs" | Out-Null

# --- backups (once) --------------------------------------------------------------------------------------------
foreach ($t in 'AgentSecurityGateway', 'ASG-Tunnel-90') {
  if (-not (Test-Path "$bak\$t.xml")) { Export-ScheduledTask -TaskName $t | Set-Content -Encoding Unicode "$bak\$t.xml" }
}
foreach ($pair in @(@($state, 'state'), @($code, 'code'), @($tun, 'tunnel'), @($home0, 'home'))) {
  if (-not (Test-Path "$bak\acl-$($pair[1]).txt")) { icacls $pair[0] /save "$bak\acl-$($pair[1]).txt" /c | Out-Null }
}

# --- accounts ------------------------------------------------------------------------------------------------
function New-Pw { $b = New-Object byte[] 30; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); 'Aa1!' + [Convert]::ToBase64String($b) }
$pws = @{}
foreach ($u in 'asgsvc', 'asgtun') {
  $pw = ConvertTo-SecureString (New-Pw) -AsPlainText -Force
  if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) { Set-LocalUser -Name $u -Password $pw -PasswordNeverExpires $true }
  else { New-LocalUser -Name $u -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description 'ASG low-privilege service account (Rev19)' | Out-Null }
  Enable-LocalUser -Name $u
  if (Get-LocalGroupMember -Group 'Administrators' -Member $u -ErrorAction SilentlyContinue) { throw "$u must not be an administrator" }
  $pws[$u] = $pw
}

# --- deny interactive / RDP / network logon for both accounts (batch logon only) ------------------------------
$sids = ('asgsvc', 'asgtun' | ForEach-Object { '*' + (Get-LocalUser $_).SID.Value }) -join ','
$inf = "$env:TEMP\asg-r19-rights.inf"; $db = "$env:TEMP\asg-r19.sdb"
secedit /export /cfg $inf /areas USER_RIGHTS | Out-Null
$lines = Get-Content $inf
foreach ($right in 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight', 'SeBatchLogonRight') {
  $i = [Array]::FindIndex($lines, [Predicate[string]] { param($l) $l -like "$right *" })
  if ($i -ge 0) { foreach ($s in $sids.Split(',')) { if ($lines[$i] -notmatch [regex]::Escape($s)) { $lines[$i] += ",$s" } } }
  else { $j = [Array]::IndexOf($lines, '[Privilege Rights]'); $lines = $lines[0..$j] + "$right = $sids" + $lines[($j + 1)..($lines.Count - 1)] }
}
$lines | Set-Content -Encoding Unicode $inf
secedit /configure /db $db /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue

# --- scripts (admin-only write, accounts read/execute) --------------------------------------------------------
Copy-Item "$Src\start_asg.ps1", "$Src\asg-tunnel.ps1" $bin -Force
icacls 'C:\ProgramData\asg' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'asgsvc:(OI)(CI)RX' 'asgtun:(OI)(CI)RX' | Out-Null
icacls $bak /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

# --- minimal ACLs --------------------------------------------------------------------------------------------
icacls $home0 /grant 'asgsvc:(X)' | Out-Null                                   # traverse only, no listing
icacls $code  /grant 'asgsvc:(OI)(CI)RX' | Out-Null                            # code: read/execute
icacls "$code\model_runtime" /grant 'asgsvc:(OI)(CI)M' | Out-Null              # relay log
icacls $state /grant 'asgsvc:(OI)(CI)M' | Out-Null                             # config, audit, runs, artifacts, logs
# subdirectories with protected (non-inherited) ACLs need explicit grants; quarantine is deliberately excluded
Get-ChildItem $state -Directory -Force | Where-Object { $_.Name -ne 'quarantine' -and (Get-Acl $_.FullName).AreAccessRulesProtected } |
  ForEach-Object { icacls $_.FullName /grant 'asgsvc:(OI)(CI)M' | Out-Null }
icacls "$state\quarantine" /inheritance:r /grant:r 'User:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null   # never readable by ASG
icacls "$state\asg-tunnel.ps1" /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null      # retired copy
# tunnel: key owned by asgtun (OpenSSH key permission check), readable only by asgtun/SYSTEM/Administrators
icacls $tun /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'asgtun:(OI)(CI)RX' | Out-Null
icacls "$tun\known_hosts" /grant 'asgtun:R' | Out-Null
icacls "$tun\logs" /grant 'asgtun:(OI)(CI)M' | Out-Null
icacls "$tun\id_ed25519" /setowner asgtun | Out-Null
icacls "$tun\id_ed25519" /inheritance:r /grant:r 'asgtun:R' 'SYSTEM:F' 'Administrators:F' | Out-Null

# --- tasks ---------------------------------------------------------------------------------------------------
$ps = 'powershell.exe'
$map = @{ 'AgentSecurityGateway' = @('asgsvc', "$bin\start_asg.ps1"); 'ASG-Tunnel-90' = @('asgtun', "$bin\asg-tunnel.ps1") }
foreach ($t in $map.Keys) {
  $u, $script = $map[$t]
  Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
  $act = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`""
  $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pws[$u]))
  Set-ScheduledTask -TaskName $t -Action $act -User "$env:COMPUTERNAME\$u" -Password $plain | Out-Null
  $plain = $null
}
$pws = $null
[GC]::Collect()
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'gateway.py|inspector_relay|asg-tunnel|8788:127.0.0.1:8788' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 2
Start-ScheduledTask AgentSecurityGateway; Start-ScheduledTask ASG-Tunnel-90
"installed"
