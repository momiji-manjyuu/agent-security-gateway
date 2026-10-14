<#
.SYNOPSIS
  Create a dedicated SSH key for an ASG tunnel and print the restricted authorized_keys line for the hub.

.DESCRIPTION
  The tunnel key can do exactly one thing: forward one loopback port. On the hub the key is installed with
  'restrict' (no shell, no pty, no agent/X11 forwarding) plus 'port-forwarding' limited by permitopen/permitlisten.
  This script only creates the key pair on THIS host (owner-only ACL) and prints the line. Installing the line on the hub is a
  person's action: on a Windows hub with an administrator account the file is
  C:\ProgramData\ssh\administrators_authorized_keys (keep its ACL: Administrators and SYSTEM only).
  The private key is never printed.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidatePattern('^[A-Za-z][A-Za-z0-9._-]{1,40}$')][string]$Name = 'asg-tunnel',
    [string]$KeyDir = (Join-Path $env:USERPROFILE '.ssh'),
    # Local forward (parent/lab -> hub API): the only destination the key may open.
    [string]$PermitOpen = '127.0.0.1:8788',
    # Reverse forward (hub -> lab runner): set this instead of PermitOpen for a -R tunnel.
    [string]$PermitListen = ''
)
$ErrorActionPreference = 'Stop'
if ($PermitOpen -and $PermitListen) { throw 'asg-tunnel: use either -PermitOpen or -PermitListen, not both' }
foreach ($value in @($PermitOpen, $PermitListen)) {
    if ($value -and $value -notmatch '^127\.0\.0\.1:\d{2,5}$') { throw 'asg-tunnel: only loopback addresses (127.0.0.1:<port>) are allowed' }
}
$key = Join-Path $KeyDir "${Name}_ed25519"
if (Test-Path -LiteralPath $key) { throw "asg-tunnel: $key already exists; refusing to overwrite" }

if ($PSCmdlet.ShouldProcess($key, 'create ed25519 key pair')) {
    New-Item -ItemType Directory -Path $KeyDir -Force | Out-Null
    ssh-keygen -t ed25519 -N '""' -C $Name -f $key -q
    icacls $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
    $pub = (Get-Content -LiteralPath "$key.pub" -Raw).Trim()
    $opts = if ($PermitListen) { "restrict,port-forwarding,permitlisten=`"$PermitListen`"" } else { "restrict,port-forwarding,permitopen=`"$PermitOpen`"" }
    Write-Output "private key: $key (owner-only, not shown)"
    Write-Output 'add this single line to the hub authorized_keys (a person does this):'
    Write-Output "$opts $pub"
}
