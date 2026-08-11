"""
reports/report_builder.py
Single entry point the dashboard/CLI calls to generate reports in any format.
Ensures the output directory exists and returns the final file path.
"""

from __future__ import annotations

from pathlib import Path

from core.config import load_config
from core.logger import get_logger
from database import repository
from reports.csv_export import alerts_to_csv, incidents_to_csv
from reports.html_report import generate_executive_summary_html, generate_incident_html_report
from reports.pdf_report import generate_incident_pdf_report

logger = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _output_dir() -> Path:
    cfg = load_config()
    out_dir = PROJECT_ROOT / cfg.report_output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def build_incident_report(incident_id: str, fmt: str = "pdf") -> str:
    out_dir = _output_dir()

    if fmt == "pdf":
        path = out_dir / f"{incident_id}_report.pdf"
        return generate_incident_pdf_report(incident_id, path)
    if fmt == "html":
        path = out_dir / f"{incident_id}_report.html"
        return generate_incident_html_report(incident_id, path)

    raise ValueError(f"Unsupported incident report format: {fmt}")


def build_executive_summary(fmt: str = "html") -> str:
    out_dir = _output_dir()
    if fmt == "html":
        path = out_dir / "executive_summary.html"
        return generate_executive_summary_html(path)
    raise ValueError(f"Unsupported executive summary format: {fmt}")


def export_alerts_csv() -> str:
    out_dir = _output_dir()
    path = out_dir / "alerts_export.csv"
    alerts = repository.get_alerts(limit=10000)
    alerts_to_csv(alerts, output_path=path)
    return str(path)


def export_incidents_csv() -> str:
    out_dir = _output_dir()
    path = out_dir / "incidents_export.csv"
    incidents = repository.get_incidents(limit=10000)
    incidents_to_csv(incidents, output_path=path)
    return str(path)
