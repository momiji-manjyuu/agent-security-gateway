# Shared loader: site settings from asg-windows.psd1 (see asg-windows.example.psd1). Dot-source from the scripts.
function Get-AsgSite([string]$Dir = $PSScriptRoot) {
    $f = Join-Path $Dir 'asg-windows.psd1'
    if (-not (Test-Path $f)) { throw "missing $f (copy asg-windows.example.psd1 and edit)" }
    $c = Import-PowerShellDataFile $f
    foreach ($k in 'StateHome', 'CodeDir', 'PythonExe', 'AsgPort', 'WorkerHost', 'WorkerUser', 'TunnelBindIP',
                   'GatewayAccount', 'TunnelAccount', 'GatewayTask', 'TunnelTask', 'BackupTag') {
        if (-not $c.ContainsKey($k)) { throw "asg-windows.psd1: missing $k" }
    }
    foreach ($k in 'StateHome', 'CodeDir', 'WorkerHost') {
        if ("$($c[$k])" -match '<|\.example$') { throw "asg-windows.psd1: $k still has a placeholder" }
    }
    return $c
}
