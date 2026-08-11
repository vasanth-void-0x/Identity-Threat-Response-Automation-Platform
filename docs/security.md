# Security Considerations

- **No offensive capability.** This project contains no exploit code,
  credential-harvesting logic, malware, or authentication-bypass techniques.
  Detection rules match *patterns* (e.g. known-suspicious PowerShell
  strings) for recognition purposes only.
- **Secrets never hardcoded.** All API keys, webhook URLs, and Wazuh
  credentials are read from environment variables via `.env` (gitignored) -
  see `core.config.WazuhAPIConfig`, which reads *only* from environment
  variables and is never persisted to YAML. `core/logger.py` includes a
  `SecretRedactingFilter` that scrubs anything matching key/token/password
  patterns before it reaches any log file; Wazuh usernames/passwords/tokens
  are never printed or logged anywhere in `integrations/wazuh_api_client.py`.
- **Simulation-first response with mandatory two-person approval for real
  actions.** See `docs/response_automation.md`. Real actions require:
  `simulation_mode` explicitly disabled, the action allowlisted, the
  incident meeting a minimum severity, the target not protected, **and**
  approval from an analyst other than the requester - self-approval is
  blocked in code (`automation.response_engine.approve_action`), not just
  policy. Every state transition (`pending_approval` → `approved`/`rejected`
  → `executed`/`failed`) is persisted and audit-logged.
- **SSL verification is on by default** for the Wazuh REST API
  (`WAZUH_VERIFY_SSL=true`) and is never silently disabled - the client
  raises a clear error on SSL failure rather than falling back to an
  insecure connection.
- **Private IPs are never sent externally.** `core/validators.is_private_ip`
  gates every threat-intelligence and GeoIP provider call. RFC 5737
  reserved/demo IP ranges are treated the same as private IPs for this
  purpose - they never reach a live external provider, whether for threat
  intelligence or GeoIP resolution (`threat_intelligence.geoip.resolve_geoip`).
- **Parameterized SQL only.** `database/repository.py` uses `?` placeholders
  exclusively - no string-formatted queries, including the new Wazuh
  sync-state and approval-workflow tables.
- **No uncontrolled background polling.** The Wazuh API is only ever
  queried in response to an explicit analyst clicking "Test Connection" or
  "Sync Wazuh Events" on the Settings page - there is no scheduler, timer,
  or automatic polling loop anywhere in the codebase.
- **Synthetic data only.** All sample data uses safe demo names (alice, bob,
  charlie, socanalyst, testadmin) and RFC 5737 reserved documentation IP
  ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) - never real
  personal data or real malicious infrastructure.
