"""parsers/csv_parser.py - Loads normalized events from a CSV export (e.g. Splunk/Wazuh export)."""

from __future__ import annotations

import csv
from pathlib import Path

from core.exceptions import ParsingError
from core.logger import get_logger
from models.event import NormalizedEvent
from parsers.normalizer import normalize_batch

logger = get_logger(__name__)


def parse_csv_file(file_path: str | Path, source: str | None = None) -> list[NormalizedEvent]:
    path = Path(file_path)
    if not path.exists():
        raise ParsingError(f"CSV log file not found: {path}")

    rows: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append({k: v for k, v in row.items() if v not in (None, "")})
    except csv.Error as exc:
        raise ParsingError(f"Failed to parse CSV {path}: {exc}") from exc

    events = normalize_batch(rows, source=source or path.stem)
    logger.info("Parsed %d events from %s", len(events), path.name)
    return events
