# Roadmap

## Near-term
- Real Splunk/Wazuh live ingestion (currently: file-based adapters only)
- Sysmon network-connection (event ID 3) correlation with PowerShell activity
  for lightweight C2-beacon heuristics
- User baseline profiles that decay/expire old known-IPs over time instead
  of growing unbounded

## Medium-term
- Pluggable rule engine allowing YAML-defined custom rules without new
  Python files
- Slack/Teams interactive incident triage (approve/deny response actions
  from chat)
- Historical trend dashboards (week-over-week alert volume, MTTR)

## Long-term / would improve for production
- Real EDR integration for host isolation (currently unimplemented by
  design - see `automation/isolate_host.py`)
- Multi-tenant support with per-team RBAC
- Kafka/queue-based ingestion for high-volume production log streams
  instead of batch JSON/CSV files
- Formal accuracy/precision measurement against labeled incident datasets
