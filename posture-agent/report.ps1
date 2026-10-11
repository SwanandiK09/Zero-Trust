param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9._-]{1,100}$')]
    [string]$User,

    [string]$ApiUrl = 'http://127.0.0.1:8090/posture',

    [switch]$SimulateFirewallDisabled
)

$ErrorActionPreference = 'Stop'

# Read the same lab key Compose uses. A local-only fallback keeps first run simple.
$secret = $env:POSTURE_SHARED_SECRET
if ([string]::IsNullOrWhiteSpace($secret)) {
    $projectEnv = Join-Path $PSScriptRoot '..\.env'
    if (Test-Path -LiteralPath $projectEnv) {
        $secretLine = Get-Content -LiteralPath $projectEnv | Where-Object { $_ -match '^\s*POSTURE_SHARED_SECRET\s*=' } | Select-Object -Last 1
        if ($secretLine -match '^\s*POSTURE_SHARED_SECRET\s*=\s*(.*)\s*$') {
            $secret = $Matches[1].Trim().Trim('"').Trim("'")
        }
    }
}
if ([string]::IsNullOrWhiteSpace($secret)) {
    $secret = 'lab-only-change-me'
}

# Read actual Windows Firewall state. This script never changes firewall settings.
$profiles = @(Get-NetFirewallProfile -Profile Domain, Private, Public | ForEach-Object {
    [PSCustomObject]@{
        name = [string]$_.Name
        enabled = [bool]$_.Enabled
    }
})
if ($profiles.Count -ne 3) {
    throw "Expected all three Windows Firewall profiles; found $($profiles.Count). No report was sent."
}

$firewallEnabled = @($profiles | Where-Object { -not $_.enabled }).Count -eq 0
$simulated = [bool]$SimulateFirewallDisabled
if ($SimulateFirewallDisabled) {
    # Safe negative test: report a synthetic value without disabling the real firewall.
    $firewallEnabled = $false
}

$report = [ordered]@{
    user = $User.ToLowerInvariant()
    device_id = $env:COMPUTERNAME
    firewall_enabled = $firewallEnabled
    profiles = $profiles
    simulated = $simulated
}
$body = $report | ConvertTo-Json -Depth 5 -Compress
$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
$message = [System.Text.Encoding]::UTF8.GetBytes("$timestamp.$body")
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($secret)
$hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
try {
    $hash = $hmac.ComputeHash($message)
} finally {
    $hmac.Dispose()
}
$signature = [System.BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()

$result = Invoke-RestMethod -Uri $ApiUrl -Method Post -ContentType 'application/json' -Body $body -Headers @{
    'X-Posture-Timestamp' = $timestamp
    'X-Posture-Signature' = $signature
}

Write-Host "Posture report accepted for $($result.user) on device $($result.device_id)."
Write-Host "Windows Firewall enabled: $($result.firewall_enabled); trust score: $($result.score)/100."
if ($result.simulated) {
    Write-Warning 'This was a lab-only test override. Your real firewall settings were not changed.'
} else {
    Write-Host 'The report used the firewall status read from this Windows device.'
}
