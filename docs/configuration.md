# Configuration

All configuration lives in `configs/*.yaml`. Secrets never go in YAML - they
come from `.env` (copy `.env.example` to `.env`).

| File | Purpose |
|---|---|
| `configs/config.yaml` | App name, database path, log level, correlation window, provider selection |
| `configs/detection_rules.yaml` | Enable/disable each rule, thresholds (failure counts, time windows) |
| `configs/risk_weights.yaml` | Point values for each rule's risk contribution |
| `configs/response_policy.yaml` | Simulation mode, protected users/hosts/networks, action allowlist |
| `configs/mitre_mapping.yaml` | Human-readable rule -> MITRE technique reference |
| `configs/logging.yaml` | Reference logging defaults |

## Environment variables (`.env`)
| Variable | Purpose | Required? |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | Enables real VirusTotal IP lookups | No (mock fallback) |
| `ABUSEIPDB_API_KEY` | Enables real AbuseIPDB IP lookups | No (mock fallback) |
| `GROQ_API_KEY` | Enables real AI incident summaries via Groq | No (mock fallback) |
| `SLACK_WEBHOOK_URL` | Enables real Slack alerts | No (simulated otherwise) |
| `EMAIL_SMTP_HOST` | Enables real email alerts | No (simulated otherwise) |
| `WAZUH_API_URL` | Wazuh REST API base URL | No (offline demo mode otherwise) |
| `WAZUH_API_USERNAME` | Wazuh REST API username | No |
| `WAZUH_API_PASSWORD` | Wazuh REST API password | No |
| `WAZUH_VERIFY_SSL` | SSL verification for Wazuh API (`true`/`false`) | No - defaults to `true` |
| `WAZUH_REQUEST_TIMEOUT` | Wazuh API request timeout in seconds | No - defaults to `10` |
| `ITRAP_DISABLE_SIMULATION` | Set `true` to allow real response actions | No - leave `false` |

## GeoIP provider (`configs/config.yaml`)
`threat_intelligence.geoip_provider` controls the Overview page's attack
source map:
- `mock` (default) - deterministic simulated locations, fully offline. The
  dashboard shows a "🟡 Demo GeoIP — Simulated Locations" badge.
- `live` - resolves real public IPs via the HTTPS ipwho.is endpoint (no key required,
  rate-limited). Private and RFC 5737 reserved/demo IPs are **always**
  simulated regardless of this setting - see `docs/security.md`. The
  dashboard shows a "🟢 Live GeoIP Data" badge when this is enabled.

Configuration is validated at startup via Pydantic models in `core/config.py`;
invalid values raise a clear `ConfigurationError`.
