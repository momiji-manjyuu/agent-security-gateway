<#
.SYNOPSIS
  Block the lab subnet from reaching services on the Hyper-V host (SSH, Docker, SMB, ...).

.DESCRIPTION
  The internal switch gives the guest a path to the host's vEthernet address. Without this rule the guest can
  talk to anything the host listens on. This script changes the Windows firewall, so it is NOT run by
  New-AsgLabVm.ps1. A person should review and run it from an elevated session.
  Host -> guest traffic (the management SSH) is unaffected: replies to host-initiated connections are allowed.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$LabCidr = '172.29.91.0/29',
    [string]$RuleName = 'ASG-Lab-block-guest-to-host'
)
$ErrorActionPreference = 'Stop'
if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
    Write-Output "rule '$RuleName' already exists; nothing to do"
    return
}
if ($PSCmdlet.ShouldProcess($LabCidr, 'add inbound block rule')) {
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -RemoteAddress $LabCidr -Profile Any -Enabled True | Out-Null
    Write-Output "added: inbound block from $LabCidr"
}
