"""
parsers/windows_event_parser.py
Parses Windows Security Event Log entries exported as XML (the format produced
by `wevtutil qe Security /f:xml` or Get-WinEvent | ConvertTo-Xml). Also accepts
a simplified JSON representation of the same fields for lab/demo use.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from core.exceptions import ParsingError
from core.logger import get_logger
from models.event import NormalizedEvent
from parsers.normalizer import normalize_batch

logger = get_logger(__name__)

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _event_to_dict(event_elem: ET.Element) -> dict:
    d: dict = {}
    system = event_elem.find("e:System", _NS)
    if system is not None:
        event_id_elem = system.find("e:EventID", _NS)
        d["event_code"] = event_id_elem.text if event_id_elem is not None else ""
        time_elem = system.find("e:TimeCreated", _NS)
        if time_elem is not None:
            d["timestamp"] = time_elem.get("SystemTime")
        computer_elem = system.find("e:Computer", _NS)
        if computer_elem is not None:
            d["hostname"] = computer_elem.text
        channel_elem = system.find("e:Channel", _NS)
        if channel_elem is not None:
            d["channel"] = channel_elem.text

    event_data = event_elem.find("e:EventData", _NS)
    if event_data is not None:
        for data_elem in event_data.findall("e:Data", _NS):
            name = data_elem.get("Name")
            if name:
                d[name] = data_elem.text

    return d


def parse_windows_event_xml(file_path: str | Path) -> list[NormalizedEvent]:
    path = Path(file_path)
    if not path.exists():
        raise ParsingError(f"Windows Event XML file not found: {path}")

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ParsingError(f"Invalid Windows Event XML in {path}: {exc}") from exc

    root = tree.getroot()
    events = root.findall("e:Event", _NS) if root.tag.endswith("Events") else [root]

    raw_dicts = [_event_to_dict(e) for e in events]
    normalized = normalize_batch(raw_dicts, source="windows_event_log")
    logger.info("Parsed %d Windows events from %s", len(normalized), path.name)
    return normalized
