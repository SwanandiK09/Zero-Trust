#!/usr/bin/env pwsh
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')]
    [string]$DeviceId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$opensslCommand = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $opensslCommand) {
    throw 'OpenSSL is required. Install OpenSSL, reopen PowerShell, then run this script again.'
}
$openssl = $opensslCommand.Source
$generated = Join-Path $PSScriptRoot 'generated'
$private = Join-Path $generated 'private'
$devices = Join-Path $generated 'devices'
$caKey = Join-Path $private 'ca.key'
$caCert = Join-Path $generated 'ca.crt'
if (-not (Test-Path -LiteralPath $caKey) -or -not (Test-Path -LiteralPath $caCert)) {
    throw 'The lab CA is missing. Run .\pki\setup-ca.ps1 first.'
}
New-Item -ItemType Directory -Force -Path $devices | Out-Null

$deviceKey = Join-Path $private "$DeviceId.key"
$deviceCsr = Join-Path $private "$DeviceId.csr"
$deviceCert = Join-Path $devices "$DeviceId.crt"
$devicePfx = Join-Path $devices "$DeviceId.pfx"
if ((Test-Path -LiteralPath $deviceKey) -or (Test-Path -LiteralPath $devicePfx)) {
    throw "A certificate for '$DeviceId' already exists. Choose another device ID or revoke/renew it deliberately."
}

function Invoke-OpenSSL {
    $openSslArgs = $args
    & $openssl @openSslArgs
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL failed: $($openSslArgs -join ' ')" }
}

Invoke-OpenSSL genrsa -out $deviceKey 2048
Invoke-OpenSSL req -new -key $deviceKey -out $deviceCsr -subj "/CN=$DeviceId"
Invoke-OpenSSL x509 -req -in $deviceCsr -CA $caCert -CAkey $caKey -CAserial (Join-Path $generated 'ca.srl') `
    -out $deviceCert -days 180 -sha256 -extfile (Join-Path $PSScriptRoot 'device.ext')
Invoke-OpenSSL pkcs12 -export -out $devicePfx -inkey $deviceKey -in $deviceCert `
    -certfile $caCert -name $DeviceId
Remove-Item -LiteralPath $deviceKey -Force

Write-Host "Certificate issued for device '$DeviceId'."
Write-Host "Import this file into the Windows user's Personal certificate store: $devicePfx"
Write-Host 'OpenSSL will ask for the CA passphrase to sign the certificate and a password to protect the PFX.'
Write-Host 'The unencrypted temporary device key was deleted after the protected PFX was created.'
