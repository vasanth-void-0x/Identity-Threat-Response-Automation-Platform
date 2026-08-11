"""
integrations/splunk_adapter.py
Optional Splunk integration adapter. This lab build does not connect to a
live Splunk instance - it provides a converter for Splunk search-result JSON
exports (splunk search ... | outputjson) into the platform's normalized
event model, so a real Splunk deployment can feed this platform without
code changes to the core detection engine.

See docs/splunk_integration.md for setup guidance and example SPL searches.
"""

from __future__ import annotations

import json
from pathlib import Path

from models.event import NormalizedEvent
from parsers.normalizer import normalize_batch


def convert_splunk_export(json_path: str | Path) -> list[NormalizedEvent]:
    """Converts a Splunk `| outputjson` search export into normalized events."""
    with open(json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    results = raw.get("result") or raw if isinstance(raw, list) else raw.get("results", [])
    mapped = []
    for r in results:
        raw_fields = r.get("_raw") if isinstance(r, dict) else None
        mapped.append({
            "timestamp": r.get("_time") or r.get("timestamp"),
            "event_code": r.get("EventCode") or r.get("event_code"),
            "user": r.get("user") or r.get("Account_Name"),
            "source_ip": r.get("src_ip") or r.get("IpAddress"),
            "hostname": r.get("host") or r.get("ComputerName"),
            "status": r.get("status"),
            "raw_splunk_event": raw_fields,
        })
    return normalize_batch(mapped, source="splunk")
