"""
parsers/sysmon_parser.py
Parses Sysmon events (JSON export format used by this lab's sample data / Wazuh
JSON alerts). Reuses windows_event_parser for raw XML Sysmon channel exports.
"""

from __future__ import annotations

from pathlib import Path

from core.logger import get_logger
from models.event import NormalizedEvent
from parsers.json_parser import parse_json_file
from parsers.windows_event_parser import parse_windows_event_xml

logger = get_logger(__name__)


def parse_sysmon_json(file_path: str | Path) -> list[NormalizedEvent]:
    events = parse_json_file(file_path, source="sysmon")
    for e in events:
        e.provider = "sysmon"
    logger.info("Parsed %d Sysmon events from %s", len(events), file_path)
    return events


def parse_sysmon_xml(file_path: str | Path) -> list[NormalizedEvent]:
    events = parse_windows_event_xml(file_path)
    for e in events:
        e.provider = "sysmon"
    return events
