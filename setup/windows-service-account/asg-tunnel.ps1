# ASG reverse tunnel gateway host -> worker host (runs as the low-privilege tunnel account).
# Exposes 127.0.0.1:<AsgPort> as <TunnelBindIP>:<AsgPort> on the worker host. Settings: asg-windows.psd1.
. (Join-Path $PSScriptRoot '_site.ps1'); $S = Get-AsgSite
$fwd = "$($S.TunnelBindIP):$($S.AsgPort):127.0.0.1:$($S.AsgPort)"; $dest = "$($S.WorkerUser)@$($S.WorkerHost)"
$ErrorActionPreference = 'Continue'
$dir = 'C:\ProgramData\asg-tunnel'
$log = "$dir\logs\asg-tunnel.log"
$ssh = "$env:WINDIR\System32\OpenSSH\ssh.exe"
function Log($m) { Add-Content -Path $log -Value ("{0} {1}" -f (Get-Date -Format s), $m) }
while ($true) {
  if ((Test-Path $log) -and (Get-Item $log).Length -gt 5MB) { Move-Item -Force $log "$log.1" }
  Log "starting ssh -R $fwd $dest as $env:USERNAME"
  & $ssh -N -i "$dir\id_ed25519" -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$dir\known_hosts" -R $fwd $dest 2>&1 | ForEach-Object { Log "ssh: $_" }
  Log ("ssh exited code {0}; retry in 10s" -f $LASTEXITCODE)
  Start-Sleep -Seconds 10
}
