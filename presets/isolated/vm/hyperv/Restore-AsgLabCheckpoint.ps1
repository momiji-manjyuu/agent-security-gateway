<#
.SYNOPSIS
  Restore a lab VM to a named checkpoint and start it. Also the human-only way to release a frozen VM.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][string]$Name,
    [string]$Label = 'baseline-clean',
    [string]$SwitchName = 'ASG-Lab-net'
)
$ErrorActionPreference = 'Stop'
if ($PSCmdlet.ShouldProcess($Name, "restore '$Label'")) {
    if ((Get-VM -Name $Name).State -ne 'Off') { Stop-VM -Name $Name -TurnOff -Force }
    Restore-VMSnapshot -VMName $Name -Name $Label -Confirm:$false
    # A freeze disconnects the NIC; reconnect only to the internal lab switch.
    Get-VMNetworkAdapter -VMName $Name | Connect-VMNetworkAdapter -SwitchName $SwitchName
    Start-VM -Name $Name
}
