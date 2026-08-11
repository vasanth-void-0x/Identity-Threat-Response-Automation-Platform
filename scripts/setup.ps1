# scripts/setup.ps1
# Sets up the Identity Threat Response Automation Platform on Windows.
# Checks Python version, creates a virtual environment, installs dependencies,
# copies .env.example to .env, and initializes the database.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "=== ITRAP Setup ===" -ForegroundColor Cyan

# 1. Check Python version
Write-Host "`n[1/6] Checking Python version..."
try {
    $pythonVersion = & python --version 2>&1
    Write-Host "Found: $pythonVersion"
    if ($pythonVersion -notmatch "Python 3\.(1[1-9]|[2-9]\d)") {
        Write-Warning "Python 3.11+ is recommended. Continuing anyway."
    }
} catch {
    Write-Error "Python not found on PATH. Install Python 3.11+ from python.org and re-run this script."
    exit 1
}

# 2. Create virtual environment
Write-Host "`n[2/6] Creating virtual environment..."
Set-Location $ProjectRoot
if (-not (Test-Path ".venv")) {
    python -m venv .venv
    Write-Host "Virtual environment created at .venv"
} else {
    Write-Host "Virtual environment already exists, skipping."
}

# 3. Activate environment
Write-Host "`n[3/6] Activating virtual environment..."
& .\.venv\Scripts\Activate.ps1

# 4. Install dependencies
Write-Host "`n[4/6] Installing dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt

# 5. Copy .env.example to .env if missing
Write-Host "`n[5/6] Configuring environment file..."
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host ".env created from .env.example (no API keys required for default operation)"
} else {
    Write-Host ".env already exists, skipping."
}

# 6. Initialize database
Write-Host "`n[6/6] Initializing database..."
python -c "from database.connection import get_connection; get_connection(); print('Database initialized.')"

Write-Host "`n=== Setup complete ===" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1. Seed demo data:  .\scripts\seed_demo.ps1"
Write-Host "  2. Start dashboard: .\scripts\start.ps1"
Write-Host "  3. Run tests:       .\scripts\run_tests.ps1"
