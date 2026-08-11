"""
integrations/wazuh_adapter.py
Optional Wazuh integration adapter. Converts Wazuh alert JSON (as written to
/var/ossec/logs/alerts/alerts.json) into the platform's normalized event
model. See docs/wazuh_integration.md for agent setup and custom rule
guidance.
"""

from __future__ import annotations

import json
from pathlib import Path

from models.event import NormalizedEvent
from parsers.normalizer import normalize_batch


def convert_wazuh_alerts(json_lines_path: str | Path) -> list[NormalizedEvent]:
    """Wazuh alerts.json is newline-delimited JSON (one alert object per line)."""
    mapped = []
    with open(json_lines_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            win = alert.get("data", {}).get("win", {}).get("eventdata", {})
            system = alert.get("data", {}).get("win", {}).get("system", {})

            mapped.append({
                "timestamp": alert.get("timestamp"),
                "event_code": system.get("eventID"),
                "user": win.get("targetUserName") or win.get("subjectUserName"),
                "source_ip": win.get("ipAddress"),
                "hostname": alert.get("agent", {}).get("name"),
                "process_name": win.get("newProcessName"),
                "command_line": win.get("commandLine"),
                "raw_wazuh_alert": alert,
            })
    return normalize_batch(mapped, source="wazuh")
