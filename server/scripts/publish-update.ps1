param(
  [Parameter(Mandatory=$true)][string]$PackageFile,
  [Parameter(Mandatory=$true)][string]$Version,
  [Parameter(Mandatory=$true)][string]$DownloadUrl,
  [string]$ServerUrl = "http://127.0.0.1:18765",
  [string]$Channel = "stable",
  [string]$Platform = "windows-x86_64",
  [string]$MinimumLicenseVersion = "0.1.0",
  [string]$AdminUsername = $(if ($env:ADMIN_USERNAME) { $env:ADMIN_USERNAME } else { "admin" }),
  [string]$AdminPassword = $env:ADMIN_PASSWORD,
  [string]$MfaCode = $env:ADMIN_MFA_CODE
)

if (!(Test-Path -LiteralPath $PackageFile)) { throw "Package file not found: $PackageFile" }
if ([string]::IsNullOrWhiteSpace($AdminPassword)) { throw "ADMIN_PASSWORD is required" }

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $PackageFile).Hash.ToLowerInvariant()
$body = @{
  version = $Version
  channel = $Channel
  platform = $Platform
  minimum_license_version = $MinimumLicenseVersion
  download_url = $DownloadUrl
  sha256 = $hash
} | ConvertTo-Json

$loginBody = @{
  username = $AdminUsername
  password = $AdminPassword
  mfa_code = $(if ([string]::IsNullOrWhiteSpace($MfaCode)) { $null } else { $MfaCode })
} | ConvertTo-Json
$session = Invoke-RestMethod `
  -Method Post `
  -Uri "$ServerUrl/api/v1/admin/auth/login" `
  -ContentType "application/json" `
  -Body $loginBody

Invoke-RestMethod `
  -Method Post `
  -Uri "$ServerUrl/api/v1/admin/updates/publish" `
  -Headers @{ "Authorization" = "Bearer $($session.access_token)" } `
  -ContentType "application/json" `
  -Body $body
