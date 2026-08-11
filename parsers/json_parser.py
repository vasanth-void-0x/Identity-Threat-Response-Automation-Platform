"""parsers/json_parser.py - Loads normalized events from a JSON log file (list of event dicts)."""

from __future__ import annotations

import json
from pathlib import Path

from core.exceptions import ParsingError
from core.logger import get_logger
from models.event import NormalizedEvent
from parsers.normalizer import normalize_batch

logger = get_logger(__name__)


def parse_json_file(file_path: str | Path, source: str | None = None) -> list[NormalizedEvent]:
    path = Path(file_path)
    if not path.exists():
        raise ParsingError(f"JSON log file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ParsingError(f"Invalid JSON in {path}: {exc}") from exc

    if isinstance(data, dict):
        data = data.get("events", [data])
    if not isinstance(data, list):
        raise ParsingError(f"Expected a JSON list of events in {path}")

    events = normalize_batch(data, source=source or path.stem)
    logger.info("Parsed %d events from %s", len(events), path.name)
    return events
