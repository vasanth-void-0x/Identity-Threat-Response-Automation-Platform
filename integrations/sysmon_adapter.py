"""
integrations/sysmon_adapter.py
Optional Sysmon integration adapter - thin wrapper over parsers/sysmon_parser
for use by integration scripts that pull directly from the Sysmon Windows
Event Log channel (Microsoft-Windows-Sysmon/Operational).
"""

from __future__ import annotations

from pathlib import Path

from models.event import NormalizedEvent
from parsers.sysmon_parser import parse_sysmon_json, parse_sysmon_xml


def convert_sysmon_export(file_path: str | Path) -> list[NormalizedEvent]:
    path = Path(file_path)
    if path.suffix.lower() == ".json":
        return parse_sysmon_json(path)
    return parse_sysmon_xml(path)
