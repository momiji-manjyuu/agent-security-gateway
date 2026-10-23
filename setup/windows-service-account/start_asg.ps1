# ASG supervisor (Rev19c). Runs as the low-privilege account asgsvc via the AgentSecurityGateway scheduled task.
# Keeps inspector relay + gateway running: health-checks /healthz and restarts both itself (Task Scheduler's
# restart-on-failure does not fire on a non-zero exit code, so the supervisor never relies on it).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot '_site.ps1'); $S = Get-AsgSite
$home0 = $S.StateHome                                      # ASG state/config live under this profile (paths use ~)
$root  = $S.CodeDir
$state = "$home0\.agent-security-gateway\disposable-search"
$python = $S.PythonExe
$health = "http://127.0.0.1:$($S.AsgPort)/healthz"
function Log($m) {
    $f = "$state\supervisor.log"
    if ((Test-Path $f) -and (Get-Item $f).Length -gt 2MB) { Move-Item -Force $f "$f.1" }
    Add-Content -Path $f -Value ("{0} {1}" -f (Get-Date -Format s), $m)
}
$env:USERPROFILE = $home0; $env:HOME = $home0              # keep ~ pointing at the existing state, not asgsvc's profile
$values = Get-Content -LiteralPath ($state + '\asg-env.json') -Raw | ConvertFrom-Json
foreach ($p in $values.psobject.Properties) { [Environment]::SetEnvironmentVariable($p.Name, [string]$p.Value, 'Process') }
$values = $null
$backoff = 5
while ($true) {
    $relay = $null; $gw = $null; $healthy = $false
    try {
        $relay = Start-Process -FilePath $python -ArgumentList @('-B', ($root + '\model_runtime\inspector_relay.py')) -WorkingDirectory ($root + '\model_runtime') -WindowStyle Hidden -PassThru
        $gw = Start-Process -FilePath $python -ArgumentList @('-B', ($root + '\gateway.py'), '--config', "$home0\.agent-security-gateway\config.json", 'serve') -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput ($state + '\gateway.stdout.log') -RedirectStandardError ($state + '\gateway.stderr.log')
        [IO.File]::WriteAllText(($state + '\pids.json'), (@{ gateway = $gw.Id; relay = $relay.Id; user = $env:USERNAME } | ConvertTo-Json))
        Log ("started gateway={0} relay={1} user={2}" -f $gw.Id, $relay.Id, $env:USERNAME)
        Start-Sleep -Seconds 20
        $fails = 0
        while (-not $gw.HasExited -and -not $relay.HasExited) {
            try { $r = Invoke-WebRequest -UseBasicParsing $health -TimeoutSec 10; if ($r.StatusCode -eq 200) { $fails = 0; $healthy = $true } else { $fails++ } } catch { $fails++ }
            if ($fails -ge 4) { Log 'healthz failed 4x'; break }
            Start-Sleep -Seconds 15
        }
        Log ("restarting (gateway_exited={0} relay_exited={1})" -f $gw.HasExited, $relay.HasExited)
    } catch {
        Log ("start error: " + $_.Exception.GetType().Name)
    } finally {
        foreach ($p in @($gw, $relay)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    }
    $backoff = if ($healthy) { 5 } else { [Math]::Min(120, $backoff * 2) }
    Start-Sleep -Seconds $backoff
}
