# Wazuh Integration

The core platform runs without Wazuh - both paths below are optional.

## Two integration paths

| Path | Module | Live connection? |
|---|---|---|
| **File export (JSON)** | `integrations/wazuh_adapter.py` | No - reads a static exported file |
| **REST API (live)** | `integrations/wazuh_api_client.py` | Yes, when `WAZUH_API_URL`/`WAZUH_API_USERNAME`/`WAZUH_API_PASSWORD` are set |

Both paths convert Wazuh records into the same `NormalizedEvent` model and
feed the same detection engine - the rest of the pipeline (detection,
correlation, scoring, MITRE mapping, dashboard) is identical either way.

## Path 1: File export (offline, no credentials needed)

`integrations/wazuh_adapter.py` parses Wazuh's newline-delimited
`alerts.json` (typically at `/var/ossec/logs/alerts/alerts.json` on the
Wazuh manager) into the platform's normalized event model.

### Agent role
Install the Wazuh agent on monitored Windows hosts; it forwards Windows
Security Event Log and Sysmon events to the manager, which applies its own
rule set before writing to `alerts.json`.

### Custom rules concept
Wazuh rules can pre-filter to just the identity-relevant event IDs this
platform cares about (4624, 4625, 4672, 4720, 4728, 4732, 4740, 4104, Sysmon
1/3/11/22), reducing noise before ingestion.

### Mapping Wazuh alerts -> normalized event model
`integrations/wazuh_adapter.py` extracts `data.win.eventdata` and
`data.win.system` fields (event ID, target user, IP, process/command line)
and maps them the same way `parsers/normalizer.py` does for other sources.

## Path 2: Live REST API (optional)

`integrations/wazuh_api_client.py` is a real client, not a placeholder - it
implements JWT authentication, pagination, timeouts, SSL verification, and
duplicate-ingestion prevention, and is covered by `tests/test_wazuh_api.py`
(all HTTP calls mocked). **It has not been validated against a live Wazuh
server in this environment** - verify the alert-retrieval endpoint against
your specific Wazuh version before relying on it in production. See the
module's docstring for the exact endpoint assumptions
(`POST /security/user/authenticate` for JWT auth, `GET /alerts` for
retrieval - Wazuh 4.x deployments that query alerts via the Wazuh Indexer/
OpenSearch API instead of the manager API will need `WAZUH_API_URL` pointed
at the indexer and may need the endpoint path adjusted).

### Configuration
Set in `.env` (never in YAML, never hardcoded):
```
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_API_USERNAME=wazuh_wui
WAZUH_API_PASSWORD=your-password
WAZUH_VERIFY_SSL=true
WAZUH_REQUEST_TIMEOUT=10
```

### Usage
On the **Settings** page, under "🔗 Wazuh API Integration":
- **Test Connection** - authenticates and reports success/failure, without
  retrieving any events.
- **Sync Wazuh Events** - retrieves alerts from the last 24 hours (up to 500
  by default), deduplicates against previously-ingested alerts (via a
  deterministic fingerprint - Wazuh's own alert ID when present, otherwise a
  hash of identifying fields), runs them through the full detection engine,
  and displays the resulting event/alert/incident counts.

**Both actions only run when you click the button** - there is no automatic
background polling, scheduled sync, or timer of any kind.

### Duplicate prevention
Every ingested alert's fingerprint is stored in the `wazuh_ingested_ids`
table. Re-running a sync with an overlapping time window will retrieve the
same alerts from the API again but skip re-ingesting ones already seen.

### Programmatic use
```python
from integrations.wazuh_api_client import sync_wazuh_events
result = sync_wazuh_events(hours_back=24, max_events=500)
print(result)  # {"success": True, "events_ingested": 12, ...}
```

## Sysmon
See `docs/sysmon_setup.md` for Sysmon-specific configuration guidance
(applies to both file-export and live-API paths, since Sysmon events flow
through the Wazuh agent either way).

## Roadmap
- Validate the REST API client against a live Wazuh 4.x deployment and
  adjust the alert-retrieval endpoint if using the Indexer API instead of
  the Manager API
- Bi-directional: push ITRAP incidents back into Wazuh's active-response
  framework for real containment in a production deployment
- Configurable polling schedule (opt-in, explicit) as an alternative to
  manual sync
