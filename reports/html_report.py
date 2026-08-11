"""
reports/html_report.py
Renders incident_report.html / executive_summary.html templates using Jinja2
with real data pulled from the database and MITRE mapper.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.exceptions import ReportGenerationError
from database import repository
from mitre.mapper import map_techniques

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


def generate_incident_html_report(incident_id: str, output_path: str | Path) -> str:
    incident = repository.get_incident(incident_id)
    if not incident:
        raise ReportGenerationError(f"Incident {incident_id} not found")

    response_actions = repository.get_response_actions(incident_id=incident_id)
    mitre_details = map_techniques(incident.get("mitre_techniques", []))

    template = _env.get_template("incident_report.html")
    html = template.render(
        incident=incident,
        ai_summary=incident.get("ai_summary") or "No AI summary generated for this incident.",
        mitre_details=mitre_details,
        response_actions=response_actions,
        data_source=repository.get_incident_data_source(incident),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    Path(output_path).write_text(html, encoding="utf-8")
    return str(output_path)


def generate_executive_summary_html(output_path: str | Path) -> str:
    stats = repository.get_overview_stats()
    template = _env.get_template("executive_summary.html")
    html = template.render(stats=stats, generated_at=datetime.now(timezone.utc).isoformat())
    Path(output_path).write_text(html, encoding="utf-8")
    return str(output_path)
