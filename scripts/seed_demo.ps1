# scripts/seed_demo.ps1
# Activates the virtual environment and seeds demo data (clears existing data first).

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

& .\.venv\Scripts\Activate.ps1
python seed_demo.py
