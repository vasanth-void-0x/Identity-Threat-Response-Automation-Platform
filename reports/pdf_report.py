"""
reports/pdf_report.py
Generates a PDF incident report using ReportLab, built entirely from real
incident/alert/response-action data pulled from the database.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from core.exceptions import ReportGenerationError
from database import repository
from mitre.mapper import map_techniques

_SEVERITY_COLORS = {
    "critical": colors.HexColor("#c0392b"),
    "high": colors.HexColor("#e67e22"),
    "medium": colors.HexColor("#f1c40f"),
    "low": colors.HexColor("#27ae60"),
}


def generate_incident_pdf_report(incident_id: str, output_path: str | Path) -> str:
    incident = repository.get_incident(incident_id)
    if not incident:
        raise ReportGenerationError(f"Incident {incident_id} not found")

    response_actions = repository.get_response_actions(incident_id=incident_id)
    mitre_details = map_techniques(incident.get("mitre_techniques", []))

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#4c1d95"), fontSize=19, leading=23)
    heading_style = ParagraphStyle("HeadingStyle", parent=styles["Heading2"], textColor=colors.HexColor("#5b21b6"), keepWithNext=True, spaceBefore=5)
    body_style = ParagraphStyle("Body", parent=styles["BodyText"], leading=14, spaceAfter=4)

    doc = SimpleDocTemplate(str(output_path), pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    story = []

    story.append(Paragraph("Identity Threat Response Automation Platform", title_style))
    story.append(Paragraph(f"Incident Report: {incident['incident_id']}", heading_style))
    story.append(Spacer(1, 12))

    severity = incident.get("severity", "low")
    sev_color = _SEVERITY_COLORS.get(severity, colors.grey)

    meta_rows = [
        ["Title", incident.get("title", "")],
        ["Severity", severity.upper()],
        ["Risk Score", f"{incident.get('risk_score', 0)}/100"],
        ["Status", incident.get("status", "")],
        ["Affected User", incident.get("user") or "N/A"],
        ["Source IP(s)", ", ".join(incident.get("source_ips", [])) or "N/A"],
        ["Hosts", ", ".join(incident.get("hosts", [])) or "N/A"],
        ["Created", incident.get("created_at", "")],
        ["Last Updated", incident.get("updated_at", "")],
    ]
    meta_table = Table(meta_rows, colWidths=[4 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 1), (1, 1), sev_color),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Executive Summary", heading_style))
    story.append(Paragraph(
        (incident.get("ai_summary") or "No AI summary generated for this incident.").replace("\n", "<br/>"),
        body_style,
    ))
    story.append(Spacer(1, 16))

    story.append(Paragraph("MITRE ATT&CK Techniques", heading_style))
    if mitre_details:
        mitre_rows = [["ID", "Name", "Tactic"]] + [[Paragraph(str(t["id"]), body_style), Paragraph(str(t["name"]), body_style), Paragraph(str(t["tactic"]), body_style)] for t in mitre_details]
        mitre_table = Table(mitre_rows, colWidths=[2.3 * cm, 5.7 * cm, 8 * cm], repeatRows=1)
        mitre_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4f6f8")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ]))
        story.append(mitre_table)
    else:
        story.append(Paragraph("No MITRE techniques mapped.", body_style))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Detection Timeline", heading_style))
    timeline = incident.get("timeline", [])
    if timeline:
        timeline_rows = [["Timestamp", "Evidence"]] + [
            [Paragraph(str(item.get("timestamp", "")), body_style), Paragraph(str(item.get("description", "")), body_style)]
            for item in timeline
        ]
        timeline_table = Table(timeline_rows, colWidths=[5 * cm, 11 * cm], repeatRows=1)
        timeline_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeaf8")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(timeline_table)
    else:
        story.append(Paragraph("No timeline evidence recorded.", body_style))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Response Actions Taken", heading_style))
    if response_actions:
        action_rows = [["Action", "Target", "Mode", "Status"]] + [
            [a["action_type"], a["target"], a["mode"], a["status"]] for a in response_actions
        ]
        action_table = Table(action_rows, colWidths=[4 * cm, 6 * cm, 3 * cm, 3 * cm])
        action_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4f6f8")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ]))
        story.append(action_table)
    else:
        story.append(Paragraph("No response actions recorded.", body_style))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Analyst Notes", heading_style))
    notes = incident.get("investigation_notes", [])
    if notes:
        for note in notes:
            story.append(Paragraph(f"- {note}", body_style))
    else:
        story.append(Paragraph("No analyst notes recorded.", body_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph(
        f"<b>Evidence Disclosure:</b> {repository.get_incident_data_source(incident)}. "
        "Response actions remain analyst-controlled and simulated unless the separate approval policy permits real actions.",
        body_style,
    ))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"Report generated: {datetime.now(timezone.utc).isoformat()}",
        ParagraphStyle("Footer", parent=body_style, fontSize=7, textColor=colors.grey),
    ))

    try:
        doc.build(story)
    except Exception as exc:  # noqa: BLE001
        raise ReportGenerationError(f"Failed to build PDF report: {exc}") from exc

    return str(output_path)
