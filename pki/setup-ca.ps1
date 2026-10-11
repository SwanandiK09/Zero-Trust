#!/usr/bin/env pwsh
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$opensslCommand = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $opensslCommand) {
    throw 'OpenSSL is required. Install OpenSSL, reopen PowerShell, then run this script again.'
}
$openssl = $opensslCommand.Source
$generated = Join-Path $PSScriptRoot 'generated'
$private = Join-Path $generated 'private'
New-Item -ItemType Directory -Force -Path $private | Out-Null

$caKey = Join-Path $private 'ca.key'
$caCert = Join-Path $generated 'ca.crt'
$serverKey = Join-Path $private 'server.key'
$serverCsr = Join-Path $private 'server.csr'
$serverCert = Join-Path $generated 'server.crt'
$serverExt = Join-Path $PSScriptRoot 'server.ext'
if ((Test-Path -LiteralPath $caKey) -or (Test-Path -LiteralPath $caCert)) {
    throw 'A lab CA already exists. This script will not overwrite it. Keep ca.key private.'
}

function Invoke-OpenSSL {
    $openSslArgs = $args
    & $openssl @openSslArgs
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL failed: $($openSslArgs -join ' ')" }
}

Invoke-OpenSSL genrsa -aes256 -out $caKey 4096
Invoke-OpenSSL req -x509 -new -key $caKey -sha256 -days 3650 -out $caCert `
    -subj '/CN=ZeroGate Lab Root CA' `
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' `
    -addext 'keyUsage=critical,keyCertSign,cRLSign'

Invoke-OpenSSL genrsa -out $serverKey 2048
Invoke-OpenSSL req -new -key $serverKey -out $serverCsr -subj '/CN=localhost'
Invoke-OpenSSL x509 -req -in $serverCsr -CA $caCert -CAkey $caKey `
    -CAserial (Join-Path $generated 'ca.srl') -CAcreateserial `
    -out $serverCert -days 365 -sha256 -extfile $serverExt

Write-Host 'Lab CA and localhost HTTPS certificate created.'
Write-Host "CA certificate: $caCert"
Write-Host 'The CA private key is passphrase-protected. Keep it secret and never commit it.'
