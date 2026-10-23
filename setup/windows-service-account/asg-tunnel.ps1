# ASG reverse tunnel .80 -> .90 (Rev19: runs as low-privilege account asgtun). Exposes 127.0.0.1:8788 as 10.90.0.1:8788 on .90.
$ErrorActionPreference = 'Continue'
$dir = 'C:\ProgramData\asg-tunnel'
$log = "$dir\logs\asg-tunnel.log"
$ssh = "$env:WINDIR\System32\OpenSSH\ssh.exe"
function Log($m) { Add-Content -Path $log -Value ("{0} {1}" -f (Get-Date -Format s), $m) }
while ($true) {
  if ((Test-Path $log) -and (Get-Item $log).Length -gt 5MB) { Move-Item -Force $log "$log.1" }
  Log "starting ssh -R 10.90.0.1:8788:127.0.0.1:8788 user@192.168.1.90 as $env:USERNAME"
  & $ssh -N -i "$dir\id_ed25519" -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$dir\known_hosts" -R 10.90.0.1:8788:127.0.0.1:8788 user@192.168.1.90 2>&1 | ForEach-Object { Log "ssh: $_" }
  Log ("ssh exited code {0}; retry in 10s" -f $LASTEXITCODE)
  Start-Sleep -Seconds 10
}
