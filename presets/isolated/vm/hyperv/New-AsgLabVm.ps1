<#
.SYNOPSIS
  Create an isolated Linux lab VM on Hyper-V (Generation 2) from a prepared cloud-image VHDX.

.DESCRIPTION
  - Internal virtual switch only (no NAT, no external switch). Guest has no route out ('offline' profile).
  - All integration services are disabled except one-way Time Synchronization.
  - cloud-init seed is a small FAT32 VHDX labelled CIDATA (no ISO tooling needed on Windows).
  - Only a PUBLIC ssh key is read. No passwords are created. No secrets go into the seed.
  - Use -WhatIf first. The script changes the Hyper-V host (switch, host-side IP, VM files).
  - It does NOT change the Windows firewall. Run Block-LabToHost.ps1 yourself (administrator) afterwards.

.EXAMPLE
  .\New-AsgLabVm.ps1 -Name asg-lab-eval -BaseVhdx D:\lab\noble.vhdx -SshPublicKeyFile D:\lab\lab_ed25519.pub -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$')][string]$Name,
    [Parameter(Mandatory)][string]$BaseVhdx,
    [Parameter(Mandatory)][string]$SshPublicKeyFile,
    [string]$VmRoot = (Join-Path $env:USERPROFILE 'Documents\ASG-Lab'),
    [string]$SwitchName = 'ASG-Lab-net',
    [string]$HostIp = '172.29.91.1',
    [string]$GuestIp = '172.29.91.2',
    [ValidateRange(24, 30)][int]$PrefixLength = 29,
    [ValidateSet('offline', 'logged_egress')][string]$Profile = 'offline',
    [string]$EgressProxyIp = '',
    [int]$EgressProxyPort = 0,
    [ValidateRange(2, 64)][int]$MemoryGB = 8,
    [ValidateRange(1, 32)][int]$Cpus = 4,
    [ValidateRange(20, 500)][int]$DiskGB = 60,
    [switch]$Start
)

$ErrorActionPreference = 'Stop'
$CommonDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'common'

function Fail($msg) { throw "asg-lab: $msg" }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'run from an elevated (administrator) session'
}
if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { Fail 'Hyper-V PowerShell module is not available' }
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { Fail "VM '$Name' already exists; refusing to modify it" }
if (-not (Test-Path -LiteralPath $BaseVhdx)) { Fail "BaseVhdx not found: $BaseVhdx" }
if (-not (Test-Path -LiteralPath $SshPublicKeyFile)) { Fail "SshPublicKeyFile not found: $SshPublicKeyFile" }
if ($Profile -eq 'logged_egress' -and (-not $EgressProxyIp -or $EgressProxyPort -le 0)) {
    Fail 'logged_egress needs -EgressProxyIp and -EgressProxyPort (the host-side logging proxy)'
}

$pub = (Get-Content -LiteralPath $SshPublicKeyFile -Raw).Trim()
if ($pub -match 'PRIVATE KEY') { Fail 'that file looks like a PRIVATE key; pass the .pub file' }
if ($pub -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/=]+( .*)?$') { Fail 'not a recognizable ssh public key' }

function Render([string]$text, [hashtable]$map) {
    foreach ($k in $map.Keys) { $text = $text.Replace($k, [string]$map[$k]) }
    if ($text -match '__[A-Z_]+__') { Fail "unfilled placeholder in template: $($Matches[0])" }
    return $text
}

$rulesFile = if ($Profile -eq 'offline') { 'nftables.offline.conf' } else { 'nftables.logged_egress.conf' }
$map = @{
    '__HOSTNAME__' = $Name; '__LAB_SSH_PUBLIC_KEY__' = $pub; '__PROFILE__' = $Profile
    '__HOST_IP__' = $HostIp; '__GUEST_IP__' = $GuestIp; '__PREFIX__' = $PrefixLength
    '__EGRESS_PROXY_IP__' = $EgressProxyIp; '__EGRESS_PROXY_PORT__' = $EgressProxyPort
}
$rules = Render (Get-Content -LiteralPath (Join-Path $CommonDir $rulesFile) -Raw) $map
$indented = ($rules.TrimEnd() -split "`r?`n" | ForEach-Object { '      ' + $_ }) -join "`n"
$routes = ''   # offline: no default route on purpose. logged_egress reaches the proxy on-link.
$userData = Render ((Get-Content -LiteralPath (Join-Path $CommonDir 'user-data.template') -Raw).Replace('__NFTABLES_RULES__', $indented)) $map
$netCfg = Render ((Get-Content -LiteralPath (Join-Path $CommonDir 'network-config.static.template') -Raw).Replace('__ROUTES__', $routes)) $map
$metaData = "instance-id: $Name-$([guid]::NewGuid().ToString('N').Substring(0,8))`nlocal-hostname: $Name`n"

$vmDir = Join-Path $VmRoot $Name
$diskPath = Join-Path $vmDir 'disk.vhdx'
$seedPath = Join-Path $vmDir 'seed-cidata.vhdx'

if ($PSCmdlet.ShouldProcess($vmDir, "create VM '$Name' (profile=$Profile, switch=$SwitchName, guest=$GuestIp)")) {
    New-Item -ItemType Directory -Path $vmDir -Force | Out-Null
    Copy-Item -LiteralPath $BaseVhdx -Destination $diskPath
    Resize-VHD -Path $diskPath -SizeBytes ($DiskGB * 1GB)

    # Seed disk: FAT32 volume labelled CIDATA
    New-VHD -Path $seedPath -SizeBytes 128MB -Dynamic | Out-Null
    $disk = Mount-VHD -Path $seedPath -Passthru | Get-Disk
    try {
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT
        $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
        Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel 'CIDATA' -Confirm:$false | Out-Null
        $root = $part.DriveLetter + ':\'
        [IO.File]::WriteAllText((Join-Path $root 'user-data'), ($userData -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
        [IO.File]::WriteAllText((Join-Path $root 'meta-data'), ($metaData -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
        [IO.File]::WriteAllText((Join-Path $root 'network-config'), ($netCfg -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
    }
    finally { Dismount-VHD -Path $seedPath }

    if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
        $ifAlias = "vEthernet ($SwitchName)"
        New-NetIPAddress -InterfaceAlias $ifAlias -IPAddress $HostIp -PrefixLength $PrefixLength | Out-Null
    }

    New-VM -Name $Name -Generation 2 -MemoryStartupBytes ($MemoryGB * 1GB) -VHDPath $diskPath -Path $vmDir -SwitchName $SwitchName | Out-Null
    Set-VM -Name $Name -ProcessorCount $Cpus -StaticMemory -AutomaticCheckpointsEnabled $false -CheckpointType Standard -AutomaticStartAction Nothing -AutomaticStopAction TurnOff
    Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftUEFICertificateAuthority'
    Add-VMHardDiskDrive -VMName $Name -Path $seedPath
    Set-VMProcessor -VMName $Name -ExposeVirtualizationExtensions $false

    # Isolation: disable every integration service except time sync (matched by its language-neutral GUID).
    foreach ($svc in Get-VMIntegrationService -VMName $Name) {
        if ($svc.Id -match '2497F4DE-E9FA-4204-80E4-4B75C46419C0') { Enable-VMIntegrationService -VMName $Name -Name $svc.Name }
        else { Disable-VMIntegrationService -VMName $Name -Name $svc.Name }
    }
    Get-VMNetworkAdapter -VMName $Name | Set-VMNetworkAdapter -MacAddressSpoofing Off -DhcpGuard On -RouterGuard On

    if ($Start) { Start-VM -Name $Name }
    Write-Output (@{ vm = $Name; profile = $Profile; guest_ip = $GuestIp; host_ip = $HostIp; switch = $SwitchName; started = [bool]$Start } | ConvertTo-Json -Compress)
    Write-Output "next: wait for 'ssh lab@$GuestIp' to work, run asg-lab-selfcheck, then Save-AsgLabCheckpoint.ps1 -Name $Name -Label baseline-clean"
}
