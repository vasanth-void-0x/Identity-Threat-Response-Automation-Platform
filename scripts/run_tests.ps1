# scripts/run_tests.ps1
# Activates the virtual environment and runs the full pytest suite.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

& .\.venv\Scripts\Activate.ps1
pytest -v
