param(
  [string]$DatabaseUrl = $env:DATABASE_URL,
  [string]$BackupDir = "$PSScriptRoot\..\backups"
)
if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) { throw "DATABASE_URL is required" }
New-Item -ItemType Directory -Force $BackupDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out = Join-Path $BackupDir "aiguard-$stamp.dump"
& pg_dump --format=custom --file=$out --dbname=$DatabaseUrl --no-owner --no-privileges
if ($LASTEXITCODE -ne 0) { throw "pg_dump failed" }
Get-ChildItem $BackupDir -Filter '*.dump' | Sort-Object LastWriteTime -Descending | Select-Object -Skip 14 | Remove-Item -Force
Write-Output $out
