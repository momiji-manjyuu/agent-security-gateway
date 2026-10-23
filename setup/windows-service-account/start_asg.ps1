# ASG supervisor (Rev19). Runs as the low-privilege account asgsvc via the AgentSecurityGateway scheduled task.
# Starts inspector relay + gateway, health-checks /healthz, and exits non-zero on failure so Task Scheduler restarts it.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$home0 = 'C:\Users\User'                                   # ASG state/config live under this profile (paths use ~)
$root  = "$home0\agent-security-gateway"
$state = "$home0\.agent-security-gateway\disposable-search"
$python = 'C:\Program Files\Python312\python.exe'
$health = 'http://127.0.0.1:8788/healthz'
function Log($m) { Add-Content -Path "$state\supervisor.log" -Value ("{0} {1}" -f (Get-Date -Format s), $m) }
$env:USERPROFILE = $home0; $env:HOME = $home0              # keep ~ pointing at the existing state, not asgsvc's profile
$values = Get-Content -LiteralPath ($state + '\asg-env.json') -Raw | ConvertFrom-Json
foreach ($p in $values.psobject.Properties) { [Environment]::SetEnvironmentVariable($p.Name, [string]$p.Value, 'Process') }
$values = $null
$relay = Start-Process -FilePath $python -ArgumentList @('-B', ($root + '\model_runtime\inspector_relay.py')) -WorkingDirectory ($root + '\model_runtime') -WindowStyle Hidden -PassThru
$gw = $null
try {
    $gw = Start-Process -FilePath $python -ArgumentList @('-B', ($root + '\gateway.py'), '--config', "$home0\.agent-security-gateway\config.json", 'serve') -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput ($state + '\gateway.stdout.log') -RedirectStandardError ($state + '\gateway.stderr.log')
    [IO.File]::WriteAllText(($state + '\pids.json'), (@{ gateway = $gw.Id; relay = $relay.Id; user = $env:USERNAME } | ConvertTo-Json))
    Log ("started gateway={0} relay={1} user={2}" -f $gw.Id, $relay.Id, $env:USERNAME)
    Start-Sleep -Seconds 20
    $fails = 0
    while (-not $gw.HasExited -and -not $relay.HasExited) {
        try { $r = Invoke-WebRequest -UseBasicParsing $health -TimeoutSec 10; if ($r.StatusCode -eq 200) { $fails = 0 } else { $fails++ } } catch { $fails++ }
        if ($fails -ge 4) { Log 'healthz failed 4x; restarting'; break }
        Start-Sleep -Seconds 15
    }
    Log ("stopping (gateway_exited={0} relay_exited={1})" -f $gw.HasExited, $relay.HasExited)
    exit 1
} finally {
    foreach ($p in @($gw, $relay)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}
