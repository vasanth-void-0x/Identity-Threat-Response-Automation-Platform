# scripts/cleanup.ps1
# Removes generated reports and logs. Only removes the demo database after
# explicit confirmation, since this is a destructive action.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== ITRAP Cleanup ===" -ForegroundColor Cyan

if (Test-Path "reports_output") {
    Remove-Item -Recurse -Force "reports_output"
    Write-Host "Removed generated reports (reports_output/)"
}

$removeLogs = Read-Host "Remove logs directory too? (y/N)"
if ($removeLogs -eq "y") {
    if (Test-Path "logs") {
        Remove-Item -Recurse -Force "logs"
        Write-Host "Removed logs/"
    }
}

$removeDb = Read-Host "Remove the demo database (database/itrap.db)? This cannot be undone. (y/N)"
if ($removeDb -eq "y") {
    Get-ChildItem "database" -Filter "itrap.db*" | Remove-Item -Force
    Write-Host "Removed demo database."
} else {
    Write-Host "Database preserved."
}

Write-Host "`nCleanup complete." -ForegroundColor Green
