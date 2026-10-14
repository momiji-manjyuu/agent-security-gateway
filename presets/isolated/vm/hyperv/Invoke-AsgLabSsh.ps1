<#
.SYNOPSIS
  Run one command in the lab guest over SSH, with a hard timeout and captured output.

.DESCRIPTION
  Windows OpenSSH can hang when started from a non-interactive parent (for example another ssh session or a service),
  because it waits on inherited stdin/console handles. This wrapper starts ssh with redirected I/O and kills it on timeout.
  Key-only, no agent forwarding, no TTY. Prints stdout, then a final line "exit=<code>".
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Command,
    [string]$GuestIp = '172.29.91.2',
    [string]$User = 'lab',
    [string]$KeyFile = (Join-Path $env:USERPROFILE 'Documents\ASG-Lab\keys\lab_ed25519'),
    [ValidateRange(5, 600)][int]$TimeoutSeconds = 60
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $KeyFile)) { throw "asg-lab: key not found: $KeyFile" }
$out = [IO.Path]::GetTempFileName(); $err = [IO.Path]::GetTempFileName()
try {
    # Pass the command base64-encoded so quoting never depends on Windows argument joining.
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
    $remote = "echo $b64 | base64 -d | bash"
    $sshArgs = @('-i', $KeyFile, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=8',
              '-o', 'ForwardAgent=no', '-T', "$User@$GuestIp", $remote)
    $p = Start-Process ssh -ArgumentList $sshArgs -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $null = $p.Handle   # cache the handle so ExitCode is readable
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) { $p.Kill(); Get-Content $out; Write-Output 'exit=timeout'; return }
    Get-Content $out
    Write-Output "exit=$($p.ExitCode)"
}
finally { Remove-Item $out, $err -Force -ErrorAction SilentlyContinue }
