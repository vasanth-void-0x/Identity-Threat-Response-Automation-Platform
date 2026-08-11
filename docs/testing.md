# Testing

Run the full suite:
```bash
pytest -v
```

All tests use an isolated temporary SQLite database (see `tests/conftest.py`)
and never call real external APIs or execute real system commands -
threat intelligence, GeoIP, AI, and Wazuh API tests only exercise mock/
patched responses; response-action tests mock every system-changing
function (`subprocess.run`, etc.). No API keys, Wazuh credentials, or
internet access are required to run tests.

## Coverage
| File | Covers |
|---|---|
| `test_parsers.py` | JSON/CSV parsing |
| `test_normalizer.py` | Raw event -> NormalizedEvent conversion |
| `test_detection_rules.py` | All 11 detection rules |
| `test_correlation.py` | Alert -> incident grouping |
| `test_correlation_timestamps.py` | Alert/incident timestamps derived from event times, not processing time |
| `test_risk_scoring.py` | Explainable scoring, severity bands |
| `test_mitre_mapping.py` | MITRE technique lookup |
| `test_threat_intelligence.py` | Mock provider + manager fallback |
| `test_geoip_routing.py` | Mock/live/cache GeoIP routing, private IP protection |
| `test_database.py` | Repository CRUD operations |
| `test_baseline.py` | Known-IP/device baseline seeding and detection engine loading |
| `test_automation.py` | Response engine policy gates (simulation only) |
| `test_approval_workflow.py` | Full approval workflow, self-approval blocking, protected targets |
| `test_wazuh_api.py` | Wazuh REST API auth, pagination, timeouts, malformed responses, dedup |
| `test_reports.py` | CSV/HTML/PDF report generation |
