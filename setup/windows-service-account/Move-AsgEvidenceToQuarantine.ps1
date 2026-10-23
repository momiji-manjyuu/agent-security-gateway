# Move test-mode evidence files (raw untrusted snippets) out of the ASG state dir into an operator-only quarantine
# folder that the gateway account cannot read. Run on the gateway host after a test-mode session.
param([string]$Src = $PSScriptRoot, [string]$Pattern = 'test_mode_evidence*.jsonl')
$ErrorActionPreference = 'Stop'
. (Join-Path $Src '_site.ps1'); $S = Get-AsgSite $Src
$state = "$($S.StateHome)\.agent-security-gateway"; $q = "$state\quarantine"; $op = Split-Path $S.StateHome -Leaf
New-Item -ItemType Directory -Force $q | Out-Null
icacls $q /inheritance:r /grant:r "${op}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
Get-ChildItem $state -File -Filter $Pattern | ForEach-Object {
  Move-Item $_.FullName (Join-Path $q ("{0}.{1}{2}" -f $_.BaseName, (Get-Date -Format yyyyMMddHHmmss), $_.Extension)) -Force
}
Get-ChildItem $q | Select-Object Name, Length | Format-Table -AutoSize | Out-String
