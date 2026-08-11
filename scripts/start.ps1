# scripts/start.ps1
# Activates the virtual environment, seeds demo data if the database is empty,
# and starts the Streamlit dashboard.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== Starting ITRAP Dashboard ===" -ForegroundColor Cyan

& .\.venv\Scripts\Activate.ps1

$eventCount = python -c "from database.repository import get_event_count; print(get_event_count())"
if ($eventCount -eq "0") {
    Write-Host "No data found - seeding demo data first..."
    python seed_demo.py
}

Write-Host "`nLaunching dashboard at http://localhost:8501 ..."
streamlit run app/dashboard.py
