param(
  [Parameter(Mandatory=$true)][string]$BackupFile,
  [string]$DatabaseUrl = $env:DATABASE_URL
)
if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) { throw "DATABASE_URL is required" }
if (!(Test-Path -LiteralPath $BackupFile)) { throw "Backup file not found: $BackupFile" }
$confirm = Read-Host "Restore will replace database objects. Type RESTORE to continue"
if ($confirm -ne "RESTORE") { throw "Restore cancelled" }
& pg_restore --clean --if-exists --no-owner --no-privileges --dbname=$DatabaseUrl $BackupFile
if ($LASTEXITCODE -ne 0) { throw "pg_restore failed" }
