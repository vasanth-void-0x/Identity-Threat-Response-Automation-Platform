# Splunk Enterprise Integration

ITRAP supports both exported Splunk JSON (`splunk_adapter.py`) and a live,
manually triggered REST connection (`splunk_api_client.py`). The verified lab
profile uses Splunk Enterprise 10.4.1 on Windows, management port 8089, index
`main`, host `SASUKE`, and sourcetype `WinEventLog:Security`.

## Configuration

Copy `.env.example` to `.env` and set:

```env
SPLUNK_URL=https://localhost:8089
SPLUNK_TOKEN=<your full token>
SPLUNK_INDEX=main
SPLUNK_SOURCETYPE=WinEventLog:Security
SPLUNK_VERIFY_SSL=false
SPLUNK_REQUEST_TIMEOUT=30
SPLUNK_MAX_EVENTS=500
```

Never commit `.env`. `SPLUNK_VERIFY_SSL=false` is only appropriate for a
trusted localhost lab using Splunk's self-signed certificate.

## Workflow

Open **Settings → Splunk Enterprise Integration**, select **Test Splunk
Connection**, then **Sync Splunk Events**. Sync is explicit (no background
polling), searches only the last 15 minutes, filters to relevant Windows
Security EventCodes, and caps results at 500 by default. Repeated syncs are
deduplicated before detection.

Supported EventCodes: 4624, 4625, 4672, 4688, 4720, 4728, 4732, 4740, 4768,
4769, 4771 and 4776.

## Verified lab SPL

```spl
index=main sourcetype="WinEventLog:Security" earliest=-24h
EventCode IN (4624,4625,4672,4688,4720,4728,4732,4740,4768,4769,4771,4776)
| stats count by EventCode
| sort - count
```

The observed lab dataset included real 4624, 4672 and 4688 events. Other
detections remain available when their corresponding Windows events occur.

## Security controls

- Bearer token read only from `.env`; never displayed or logged.
- Bounded queries and a 1,000-event hard maximum.
- Index/sourcetype input validation.
- Timeout, connection, SSL and authorization error handling.
- Fingerprint-based duplicate prevention.
- Manual sync only.

## Troubleshooting

- `401/403`: recreate the token or verify its user permissions.
- SSL error: keep verification enabled for valid certificates; use `false`
  only on the trusted localhost lab.
- No results: confirm index, sourcetype, time window and relevant EventCodes.
- Connection refused: confirm Splunk management port 8089 is running.
