"""
parsers/powershell_parser.py
Parses PowerShell Script Block Logging events (Event ID 4104) from JSON export.
Flags suspicious indicators inline for downstream detection rules.
"""

from __future__ import annotations

from pathlib import Path

from core.constants import SUSPICIOUS_POWERSHELL_INDICATORS
from core.logger import get_logger
from models.event import NormalizedEvent
from parsers.json_parser import parse_json_file

logger = get_logger(__name__)


def contains_suspicious_indicator(command_line: str | None) -> list[str]:
    if not command_line:
        return []
    lowered = command_line.lower()
    return [ind for ind in SUSPICIOUS_POWERSHELL_INDICATORS if ind in lowered]


def parse_powershell_events(file_path: str | Path) -> list[NormalizedEvent]:
    events = parse_json_file(file_path, source="powershell_logging")
    for e in events:
        indicators = contains_suspicious_indicator(e.command_line)
        if indicators:
            e.metadata["suspicious_indicators"] = indicators
    logger.info("Parsed %d PowerShell script block events from %s", len(events), file_path)
    return events
