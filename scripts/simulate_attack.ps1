# scripts/simulate_attack.ps1
# SAFE DEMO SCRIPT - does not perform any real attack, exploitation, or
# unauthorized action. It only submits pre-built synthetic sample events
# (sample_data/correlated_attack.json) into the platform's local database
# to demonstrate the detection -> correlation -> incident pipeline live.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "=== ITRAP Synthetic Attack Simulation (safe, local, synthetic data only) ===" -ForegroundColor Yellow

& .\.venv\Scripts\Activate.ps1

python -c @"
from parsers.json_parser import parse_json_file
from detection_engine.engine import DetectionEngine
from database import repository

events = parse_json_file('sample_data/correlated_attack.json', source='simulated_attack')
repository.save_events(events)

engine = DetectionEngine()
alerts, incidents = engine.run(events)
repository.save_alerts(alerts)
repository.save_incidents(incidents)

print(f'Injected {len(events)} synthetic events')
print(f'Generated {len(alerts)} alert(s) -> {len(incidents)} incident(s)')
for inc in incidents:
    print(f'  Incident {inc.incident_id}: {inc.title} (severity: {inc.severity}, score: {inc.risk_score})')
"@

Write-Host "`nOpen the dashboard (scripts/start.ps1) and check the Overview / Incident Details pages." -ForegroundColor Green
