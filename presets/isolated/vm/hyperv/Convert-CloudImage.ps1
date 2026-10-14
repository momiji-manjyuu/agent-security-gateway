<#
.SYNOPSIS
  Download a Ubuntu cloud image, verify its SHA-256 against the publisher's list, and convert it to VHDX.

.DESCRIPTION
  Conversion runs in a throw-away Docker container (qemu-img), so nothing is installed on the host.
  Default source is Canonical's official cloud-images site. The checksum list is fetched from the same site,
  so this detects corruption and partial downloads; it does not prove authenticity against a compromised site.
  Pass -ExpectedSha256 to pin a value you obtained another way.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$OutDir = (Join-Path $env:USERPROFILE 'Documents\ASG-Lab\images'),
    [string]$ImageName = 'noble-server-cloudimg-amd64.img',
    [string]$BaseUrl = 'https://cloud-images.ubuntu.com/noble/current',
    [string]$ExpectedSha256 = '',
    # Throw-away converter container. alpine:3 needs a pull; a Debian/Ubuntu-based image already present locally also works.
    [string]$ConverterImage = 'alpine:3'
)
$ErrorActionPreference = 'Stop'
if ($BaseUrl -notmatch '^https://cloud-images\.ubuntu\.com/') { throw 'asg-lab: only cloud-images.ubuntu.com is allowed here' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$img = Join-Path $OutDir $ImageName
$vhdx = Join-Path $OutDir ([IO.Path]::GetFileNameWithoutExtension($ImageName) + '.vhdx')

if ($PSCmdlet.ShouldProcess($BaseUrl, "download $ImageName and convert to VHDX")) {
    $raw = (Invoke-WebRequest -UseBasicParsing "$BaseUrl/SHA256SUMS").Content
    $sums = if ($raw -is [byte[]]) { [Text.Encoding]::UTF8.GetString($raw) } else { [string]$raw }
    $line = ($sums -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match ('[ *]' + [regex]::Escape($ImageName) + '$') } | Select-Object -First 1)
    if (-not $line) { throw "asg-lab: $ImageName not in SHA256SUMS" }
    $want = if ($ExpectedSha256) { $ExpectedSha256.ToLower() } else { ($line -split '\s+')[0].ToLower() }
    if (-not (Test-Path -LiteralPath $img)) { Invoke-WebRequest -UseBasicParsing "$BaseUrl/$ImageName" -OutFile $img }
    $got = (Get-FileHash -LiteralPath $img -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $want) { Remove-Item -LiteralPath $img -Force; throw "asg-lab: SHA-256 mismatch (got $got)" }
    $out = [IO.Path]::GetFileName($vhdx)
    $install = if ($ConverterImage -match "alpine") { "apk add --no-cache qemu-img" } else { "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends qemu-utils" }
    docker run --rm -v "${OutDir}:/w" $ConverterImage sh -c "$install >/dev/null && qemu-img convert -f qcow2 -O vhdx -o subformat=dynamic /w/$ImageName /w/$out"
    $dockerExit = $LASTEXITCODE
    if ($dockerExit -ne 0 -or -not (Test-Path -LiteralPath $vhdx)) { throw 'asg-lab: conversion failed' }
    Write-Output (@{ image = $img; sha256 = $got; vhdx = $vhdx } | ConvertTo-Json -Compress)
}
