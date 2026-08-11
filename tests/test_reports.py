"""tests/test_reports.py - Tests for CSV/HTML/PDF report generation (no network calls)."""

from pathlib import Path

from database import repository
from models.incident import Incident
from reports.csv_export import alerts_to_csv, incidents_to_csv
from reports.html_report import generate_executive_summary_html, generate_incident_html_report
from reports.pdf_report import generate_incident_pdf_report


def _seed_incident():
    incident = Incident(title="Test Incident", severity="high", risk_score=75, user="alice",
                         mitre_techniques=["T1110"])
    repository.save_incidents([incident])
    return incident


def test_incidents_to_csv():
    incident = _seed_incident()
    incidents = repository.get_incidents()
    csv_content = incidents_to_csv(incidents)
    assert incident.incident_id in csv_content
    assert "Test Incident" in csv_content


def test_alerts_to_csv_empty():
    assert alerts_to_csv([]) == ""


def test_generate_incident_html_report(tmp_path):
    incident = _seed_incident()
    output_path = tmp_path / "report.html"
    result_path = generate_incident_html_report(incident.incident_id, output_path)
    content = Path(result_path).read_text(encoding="utf-8")
    assert "Test Incident" in content
    assert "HIGH" in content.upper()


def test_generate_executive_summary_html(tmp_path):
    _seed_incident()
    output_path = tmp_path / "summary.html"
    result_path = generate_executive_summary_html(output_path)
    content = Path(result_path).read_text(encoding="utf-8")
    assert "SOC Executive Summary" in content


def test_generate_incident_pdf_report(tmp_path):
    incident = _seed_incident()
    output_path = tmp_path / "report.pdf"
    result_path = generate_incident_pdf_report(incident.incident_id, output_path)
    assert Path(result_path).exists()
    assert Path(result_path).stat().st_size > 0


def test_html_report_missing_incident_raises(tmp_path):
    from core.exceptions import ReportGenerationError
    import pytest
    with pytest.raises(ReportGenerationError):
        generate_incident_html_report("INC-DOESNOTEXIST", tmp_path / "x.html")
