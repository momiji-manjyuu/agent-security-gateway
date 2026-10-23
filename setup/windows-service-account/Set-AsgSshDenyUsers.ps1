# Rev20: deny SSH logins for the ASG service accounts. Run elevated on the ASG host (best as a one-shot SYSTEM task,
# so an sshd restart cannot kill it). Backs up sshd_config, inserts DenyUsers before the first Match block,
# validates with sshd -t, restarts sshd, then rolls back unless a fresh admin login creates $Marker within 180 s.
param([string]$Marker = 'C:\ProgramData\asg\r20-login-ok')
$ErrorActionPreference = 'Stop'
$cfg = 'C:\ProgramData\ssh\sshd_config'; $bak = "$cfg.bak-r20"; $log = 'C:\ProgramData\asg\r20-sshd.log'
function L($m) { Add-Content $log ("{0} {1}" -f (Get-Date -Format s), $m) }
Remove-Item $Marker -ErrorAction SilentlyContinue
if (-not (Test-Path $bak)) { Copy-Item $cfg $bak }
$lines = Get-Content $cfg
if (-not ($lines -match '^\s*DenyUsers\b')) {
  $deny = "DenyUsers asgsvc asgtun $($env:COMPUTERNAME.ToLower())\asgsvc $($env:COMPUTERNAME.ToLower())\asgtun"
  $i = [Array]::FindIndex([string[]]$lines, [Predicate[string]] { param($l) $l -match '^\s*Match\s' })
  if ($i -lt 0) { $lines += $deny } else { $lines = $lines[0..($i - 1)] + '# Rev20: ASG service accounts never log in over SSH' + $deny + '' + $lines[$i..($lines.Count - 1)] }
  [IO.File]::WriteAllLines($cfg, [string[]]$lines)
}
$t = & "$env:WINDIR\System32\OpenSSH\sshd.exe" -t 2>&1
if ($LASTEXITCODE -ne 0) { Copy-Item $bak $cfg -Force; L "sshd -t failed, restored: $t"; exit 1 }
L 'sshd -t ok; restarting'
Restart-Service sshd -Force
for ($k = 0; $k -lt 36; $k++) { Start-Sleep 5; if (Test-Path $Marker) { L 'fresh login confirmed; keeping'; Remove-Item $Marker; exit 0 } }
Copy-Item $bak $cfg -Force; Restart-Service sshd -Force; L 'no fresh login within 180s: ROLLED BACK'
