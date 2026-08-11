"""reports/csv_export.py - CSV export for alerts and incidents."""

from __future__ import annotations

import csv
import io
from pathlib import Path


def alerts_to_csv(alerts: list[dict], output_path: str | Path | None = None) -> str:
    if not alerts:
        return ""

    fieldnames = [
        "alert_id", "rule_name", "title", "created_at", "user", "source_ip",
        "hostname", "final_score", "severity", "status", "incident_id",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for a in alerts:
        writer.writerow(a)

    content = buffer.getvalue()
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
    return content


def incidents_to_csv(incidents: list[dict], output_path: str | Path | None = None) -> str:
    if not incidents:
        return ""

    fieldnames = [
        "incident_id", "title", "created_at", "updated_at", "user", "severity",
        "risk_score", "status", "is_false_positive",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for i in incidents:
        writer.writerow(i)

    content = buffer.getvalue()
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
    return content
