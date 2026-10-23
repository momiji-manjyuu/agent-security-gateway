# Deploy a new gateway.py/proxy.py to the gateway host: backup, copy, run the test suite, validate the live config,
# restart. Rolls back the code automatically if tests or validation fail. Run elevated on the gateway host.
#   .\Deploy-AsgUpdate.ps1 -From <dir with gateway.py, proxy.py> -Tag r21
param([Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string]$Tag, [string]$Src = $PSScriptRoot)
$ErrorActionPreference = 'Continue'
. (Join-Path $Src '_site.ps1'); $S = Get-AsgSite $Src
$d = $S.CodeDir; $py = $S.PythonExe; $cfg = "$($S.StateHome)\.agent-security-gateway\config.json"
$files = 'gateway.py', 'proxy.py'
foreach ($f in $files) { if (-not (Test-Path "$d\$f.bak-$Tag")) { Copy-Item "$d\$f" "$d\$f.bak-$Tag" }; Copy-Item (Join-Path $From $f) "$d\$f" -Force }
if (-not (Test-Path "$cfg.bak-$Tag")) { Copy-Item $cfg "$cfg.bak-$Tag" }
function Restore { foreach ($f in $files) { Copy-Item "$d\$f.bak-$Tag" "$d\$f" -Force } }
Push-Location "$d\tests"
$t = & $py -B -m unittest test_gateway test_boundaries test_guard_tuning test_run_scoped_agents test_input_guard_test_mode 2>&1 | Select-String -Pattern '^(Ran|OK|FAILED)'
Pop-Location; $t
if (-not ($t -match '^OK')) { Restore; 'TESTS FAILED - code rolled back'; exit 1 }
# validate-config needs the env-var names the config references (values come from the operator's env file)
$envFile = "$($S.StateHome)\.agent-security-gateway\disposable-search\asg-env.json"
if (Test-Path $envFile) { (Get-Content -LiteralPath $envFile -Raw | ConvertFrom-Json).psobject.Properties | ForEach-Object { [Environment]::SetEnvironmentVariable($_.Name, [string]$_.Value, 'Process') } }
$v = & $py -B "$d\gateway.py" --config $cfg validate-config 2>&1 | Select-Object -Last 1; $v
if (-not ($v -match '"ok": true')) { Restore; 'VALIDATION FAILED - code rolled back, not restarted'; exit 1 }
Stop-ScheduledTask $S.GatewayTask; Start-Sleep 2
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'gateway.py|inspector_relay' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-ScheduledTask $S.GatewayTask; Start-Sleep 25
try { 'healthz ' + (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$($S.AsgPort)/healthz" -TimeoutSec 5).StatusCode } catch { 'healthz FAILED - roll back with: copy *.bak-' + $Tag }
