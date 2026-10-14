<#
.SYNOPSIS
  Kill-switch for a lab VM: cut the network, then pause or save the VM so evidence is kept.

.DESCRIPTION
  Runs on the HOST, never inside the guest. One-way: it only lowers privilege.
  Releasing a frozen VM is a separate, deliberate human action (Restore-AsgLabCheckpoint.ps1 or manual).
  -Destroy additionally turns the VM off (loses RAM state). Default keeps memory (Save-VM) for forensics.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][string]$Name,
    [string]$Reason = 'manual',
    [switch]$Destroy
)
$ErrorActionPreference = 'Stop'
$vm = Get-VM -Name $Name
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
if ($PSCmdlet.ShouldProcess($Name, "freeze ($Reason)")) {
    # 1. Network first: nothing leaves, even if the guest keeps running for a moment.
    Get-VMNetworkAdapter -VMName $Name | Disconnect-VMNetworkAdapter
    # 2. Keep evidence.
    if ($Destroy) { Stop-VM -Name $Name -TurnOff -Force }
    else { Save-VM -Name $Name }
    $log = Join-Path (Split-Path -Parent $vm.Path) "freeze-$Name-$stamp.json"
    @{ vm = $Name; at = $stamp; reason = $Reason; destroyed = [bool]$Destroy; state = (Get-VM -Name $Name).State.ToString() } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $log -Encoding UTF8
    Write-Output $log
}
