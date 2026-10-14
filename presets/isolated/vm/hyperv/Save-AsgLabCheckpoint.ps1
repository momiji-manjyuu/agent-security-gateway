<#
.SYNOPSIS
  Create a named checkpoint (e.g. baseline-clean) of a lab VM. Lab VMs are restored from it after every evaluation.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{1,48}$')][string]$Label
)
$ErrorActionPreference = 'Stop'
if ($PSCmdlet.ShouldProcess($Name, "checkpoint '$Label'")) {
    Checkpoint-VM -Name $Name -SnapshotName $Label
    Get-VMSnapshot -VMName $Name | Select-Object Name, CreationTime | Format-Table -AutoSize | Out-String
}
