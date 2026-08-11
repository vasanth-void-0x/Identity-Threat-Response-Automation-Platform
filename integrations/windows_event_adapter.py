"""
integrations/windows_event_adapter.py
Optional adapter for live Windows Security Event Log ingestion, wrapping
parsers/windows_event_parser. In a real deployment this would be invoked by
scripts/setup.ps1's scheduled export (wevtutil qe Security /f:xml) piped
into this platform's sample_data/ ingestion path.
"""

from __future__ import annotations

from pathlib import Path

from models.event import NormalizedEvent
from parsers.windows_event_parser import parse_windows_event_xml


def convert_windows_event_export(xml_path: str | Path) -> list[NormalizedEvent]:
    return parse_windows_event_xml(xml_path)
