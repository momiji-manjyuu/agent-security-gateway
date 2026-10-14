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
$sshArgs = "-N -T -i `"$KeyFile`" -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 " +
           "-o StrictHostKeyChecking=yes -L 127.0.0.1:${LocalPort}:127.0.0.1:${HubPort} ${HubUser}@${HubHost}"
$plan = [ordered]@{ task = $TaskName; run = "$ssh $sshArgs"; trigger = 'at logon'; restart = 'every 1 minute, unlimited'; runs_as = $env:USERNAME }
if (-not $Apply) { $plan | ConvertTo-Json; Write-Output 'plan only. Re-run with -Apply to register the task.'; return }

# The hub host key must already be trusted (StrictHostKeyChecking=yes): connect once by hand and verify the fingerprint.
$action = New-ScheduledTaskAction -Execute $ssh -Argument $sshArgs
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited -Description 'ASG loopback tunnel (managed by asg presets)' | Out-Null
Write-Output "registered task $TaskName (starts at next logon; start now: Start-ScheduledTask $TaskName)"
