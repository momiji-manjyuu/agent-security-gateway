# Move the ASG gateway and tunnel scheduled tasks from SYSTEM to dedicated low-privilege local accounts.
# Run elevated on the gateway host. Idempotent. Settings: asg-windows.psd1 (next to this script).
# Writes backups (C:\ProgramData\asg\<BackupTag>) used by Rollback-AsgServiceAccounts.ps1.
# Passwords are random, never printed or stored; only Task Scheduler keeps them. Re-run to rotate.
param([string]$Src = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
. (Join-Path $Src '_site.ps1'); $S = Get-AsgSite $Src
$GA = $S.GatewayAccount; $TA = $S.TunnelAccount; $GT = $S.GatewayTask; $TT = $S.TunnelTask
$home0 = $S.StateHome
$state = "$home0\.agent-security-gateway"
$code  = $S.CodeDir
$bin   = 'C:\ProgramData\asg\bin'
$tun   = 'C:\ProgramData\asg-tunnel'
$bak   = "C:\ProgramData\asg\$($S.BackupTag)"
New-Item -ItemType Directory -Force $bin, $bak, "$tun\logs" | Out-Null

# --- backups (once) --------------------------------------------------------------------------------------------
foreach ($t in $GT, $TT) {
  if (-not (Test-Path "$bak\$t.xml")) { Export-ScheduledTask -TaskName $t | Set-Content -Encoding Unicode "$bak\$t.xml" }
}
foreach ($pair in @(@($state, 'state'), @($code, 'code'), @($tun, 'tunnel'), @($home0, 'home'))) {
  if (-not (Test-Path "$bak\acl-$($pair[1]).txt")) { icacls $pair[0] /save "$bak\acl-$($pair[1]).txt" /c | Out-Null }
}

# --- accounts ------------------------------------------------------------------------------------------------
function New-Pw { $b = New-Object byte[] 30; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); 'Aa1!' + [Convert]::ToBase64String($b) }
$pws = @{}
foreach ($u in $GA, $TA) {
  $pw = ConvertTo-SecureString (New-Pw) -AsPlainText -Force
  if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) { Set-LocalUser -Name $u -Password $pw -PasswordNeverExpires $true }
  else { New-LocalUser -Name $u -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description 'ASG low-privilege service account' | Out-Null }
  Enable-LocalUser -Name $u
  if (Get-LocalGroupMember -Group 'Administrators' -Member $u -ErrorAction SilentlyContinue) { throw "$u must not be an administrator" }
  $pws[$u] = $pw
}

# --- deny interactive / RDP / network logon for both accounts (batch logon only) ------------------------------
$sids = ($GA, $TA | ForEach-Object { '*' + (Get-LocalUser $_).SID.Value }) -join ','
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
Copy-Item "$Src\start_asg.ps1", "$Src\asg-tunnel.ps1", "$Src\_site.ps1", "$Src\asg-windows.psd1" $bin -Force
icacls 'C:\ProgramData\asg' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' "${GA}:(OI)(CI)RX" "${TA}:(OI)(CI)RX" | Out-Null
icacls $bak /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

# --- minimal ACLs --------------------------------------------------------------------------------------------
icacls $home0 /grant "${GA}:(X)" | Out-Null                                   # traverse only, no listing
icacls $code  /grant "${GA}:(OI)(CI)RX" | Out-Null                            # code: read/execute
icacls "$code\model_runtime" /grant "${GA}:(OI)(CI)M" | Out-Null              # relay log
icacls $state /grant "${GA}:(OI)(CI)M" | Out-Null                             # config, audit, runs, artifacts, logs
# subdirectories with protected (non-inherited) ACLs need explicit grants; quarantine is deliberately excluded
Get-ChildItem $state -Directory -Force | Where-Object { $_.Name -ne 'quarantine' -and (Get-Acl $_.FullName).AreAccessRulesProtected } |
  ForEach-Object { icacls $_.FullName /grant "${GA}:(OI)(CI)M" | Out-Null }
$op = Split-Path $home0 -Leaf
New-Item -ItemType Directory -Force "$state\quarantine" | Out-Null
icacls "$state\quarantine" /inheritance:r /grant:r "${op}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null   # never readable by ASG
icacls "$state\asg-tunnel.ps1" /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null      # retired copy
# tunnel: key owned by the tunnel account (OpenSSH key permission check), readable only by it/SYSTEM/Administrators
icacls $tun /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' "${TA}:(OI)(CI)RX" | Out-Null
icacls "$tun\known_hosts" /grant "${TA}:R" | Out-Null
icacls "$tun\logs" /grant "${TA}:(OI)(CI)M" | Out-Null
icacls "$tun\id_ed25519" /setowner $TA | Out-Null
icacls "$tun\id_ed25519" /inheritance:r /grant:r "${TA}:R" 'SYSTEM:F' 'Administrators:F' | Out-Null

# --- tasks ---------------------------------------------------------------------------------------------------
$ps = 'powershell.exe'
$map = @{ $GT = @($GA, "$bin\start_asg.ps1"); $TT = @($TA, "$bin\asg-tunnel.ps1") }
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
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "gateway.py|inspector_relay|asg-tunnel|:127.0.0.1:$($S.AsgPort)" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 2
Start-ScheduledTask $GT; Start-ScheduledTask $TT
"installed"
