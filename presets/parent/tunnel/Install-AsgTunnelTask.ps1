<#
.SYNOPSIS
  Keep an ASG loopback tunnel running: a scheduled task that starts at logon and restarts ssh when it drops.

.DESCRIPTION
  Creates (or, with -Remove, deletes) ONE scheduled task. This is a standing configuration change, so the default is to
  print the plan only. Pass -Apply to actually register it.
  The ssh command is fixed: key-only, no shell (-N), ExitOnForwardFailure, keepalives, a single loopback forward.
  Nothing secret is stored in the task; it references the key file path only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HubHost,
    [Parameter(Mandatory)][string]$HubUser,
    [string]$KeyFile = (Join-Path $env:USERPROFILE '.ssh\asg-tunnel_ed25519'),
    [string]$LocalPort = '8788',
    [string]$HubPort = '8788',
    [string]$TaskName = 'ASG-Tunnel',
    [switch]$Apply,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
if ($HubHost -notmatch '^[A-Za-z0-9._-]+$' -or $HubUser -notmatch '^[A-Za-z0-9._-]+$') { throw 'asg-tunnel: bad host or user' }
foreach ($p in @($LocalPort, $HubPort)) { if ($p -notmatch '^\d{2,5}$') { throw 'asg-tunnel: bad port' } }

if ($Remove) {
    if ($Apply) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false; Write-Output "removed task $TaskName" }
    else { Write-Output "plan: remove scheduled task $TaskName (pass -Apply)" }
    return
}
if (-not (Test-Path -LiteralPath $KeyFile)) { throw "asg-tunnel: key not found: $KeyFile (run New-AsgTunnelKey.ps1 first)" }

$ssh = (Get-Command ssh).Source
$sshArgs = "-N -T -i `"$KeyFile`" -o BatchMode=yes -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 " +
           "-o StrictHostKeyChecking=yes -L 127.0.0.1:${LocalPort}:127.0.0.1:${HubPort} ${HubUser}@${HubHost}"

# The task itself loops: when ssh ends for ANY reason (network drop, hub restart, killed) wait and start it again.
# Task Scheduler's own "restart on failure" does not fire for these cases, so it is not relied on.
$loop = "while (`$true) { & '$ssh' $sshArgs; Start-Sleep -Seconds 10 }"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($loop))
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$psArgs = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $encoded"

$plan = [ordered]@{ task = $TaskName; loop = $loop; trigger = 'at logon'; retry = 'ssh restarted 10 seconds after it ends, forever'; runs_as = $env:USERNAME }
if (-not $Apply) { $plan | ConvertTo-Json; Write-Output 'plan only. Re-run with -Apply to register (an existing task with this name is replaced).'; return }

# The hub host key must already be trusted (StrictHostKeyChecking=yes): connect once by hand and verify the fingerprint.
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
$action = New-ScheduledTaskAction -Execute $ps -Argument $psArgs
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited -Description 'ASG loopback tunnel (managed by asg presets)' | Out-Null
Write-Output "registered task $TaskName (starts at next logon; start now: Start-ScheduledTask $TaskName)"
