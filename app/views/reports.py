"""app/views/reports.py - Report generation and retrieval workspace.

Reuses the existing report_builder / html_report / pdf_report pipeline
end-to-end; this view is presentation only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from app.theme import page_header
from app.utils.data_mode import filter_incidents
from app.utils.formatting import format_timestamp, severity_badge
from core.config import load_config
from database import repository
from reports.report_builder import build_executive_summary, build_incident_report

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _reports_dir() -> Path:
    cfg = load_config()
    out_dir = PROJECT_ROOT / cfg.report_output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def render() -> None:
    mode = st.session_state.get("data_mode", "Demo Data")
    page_header("Reports", "Generate and retrieve PDF/HTML incident reports without leaving the workspace.")

    all_alerts = repository.get_alerts(limit=5000)
    incidents = filter_incidents(repository.get_incidents(limit=500), all_alerts, mode)
    incident_ids = [item["incident_id"] for item in incidents]

    pending = st.session_state.pop("_prefill_report_incident", None)
    if pending and pending in incident_ids and st.session_state.get("report_incident_select") != pending:
        st.session_state["report_incident_select"] = pending

    generate_tab, browse_tab = st.tabs(["Generate report", "Existing reports"])

    with generate_tab:
        selected = st.selectbox(
            "Search / select incident", incident_ids, index=None,
            placeholder="Choose an incident to report on", key="report_incident_select",
        )
        incident = repository.get_incident(selected) if selected else None
        if incident:
            hero = st.columns(5)
            hero[0].metric("Severity", incident["severity"].upper())
            hero[1].metric("Risk", f"{incident['risk_score']}/100")
            hero[2].metric("Status", str(incident["status"]).replace("_", " ").title())
            hero[3].metric("User", incident.get("user") or "Unknown")
            hero[4].metric("Created", format_timestamp(incident["created_at"]))
            st.markdown(f"**{incident['title']}**")
            st.markdown(severity_badge(incident["severity"]))

            pdf_col, html_col = st.columns(2)
            with pdf_col:
                if st.button("Generate PDF report", use_container_width=True, key="gen_pdf"):
                    path = build_incident_report(selected, fmt="pdf")
                    st.session_state["_last_report_path"] = path
                    st.success(f"PDF report built · `{Path(path).name}`")
                if st.session_state.get("_last_report_path", "").endswith(".pdf") and selected in st.session_state.get("_last_report_path", ""):
                    with open(st.session_state["_last_report_path"], "rb") as handle:
                        st.download_button("Download PDF", handle, file_name=Path(st.session_state["_last_report_path"]).name, key="dl_pdf_now")
            with html_col:
                if st.button("Generate HTML report", use_container_width=True, key="gen_html"):
                    path = build_incident_report(selected, fmt="html")
                    st.session_state["_last_html_report_path"] = path
                    st.success(f"HTML report built · `{Path(path).name}`")
                if st.session_state.get("_last_html_report_path", "").endswith(".html") and selected in st.session_state.get("_last_html_report_path", ""):
                    with open(st.session_state["_last_html_report_path"], "r", encoding="utf-8") as handle:
                        st.download_button("Download HTML", handle.read(), file_name=Path(st.session_state["_last_html_report_path"]).name, key="dl_html_now")

            with st.expander("More exports"):
                st.caption("Executive summary and raw evidence CSV, built from the same underlying data.")
                if st.button("Generate executive summary (HTML)", key="gen_exec"):
                    path = build_executive_summary(fmt="html")
                    with open(path, "r", encoding="utf-8") as handle:
                        st.download_button("Download executive summary", handle.read(), file_name=Path(path).name, key="dl_exec")
        else:
            st.info("Choose an incident above to preview its summary and generate a report.")

    with browse_tab:
        _render_existing_reports(mode)


def _render_existing_reports(mode: str) -> None:
    out_dir = _reports_dir()
    files = sorted(
        [p for p in out_dir.glob("*_report.*") if p.suffix in (".pdf", ".html")],
        key=lambda p: p.stat().st_mtime, reverse=True,
    )
    if not files:
        st.info("No generated reports yet. Build one from the Generate report tab.")
        return

    for path in files[:40]:
        incident_id = path.name.rsplit("_report.", 1)[0]
        incident = repository.get_incident(incident_id)
        severity = incident["severity"].upper() if incident else "UNKNOWN"
        created = format_timestamp(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat())
        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([2.4, 1, 1.3, 1.3])
            c1.write(f"**{path.name}**")
            c2.write(severity)
            c3.write(created)
            with c4:
                if path.suffix == ".pdf":
                    with open(path, "rb") as handle:
                        st.download_button("Download", handle, file_name=path.name, key=f"dl_{path.name}")
                else:
                    with open(path, "r", encoding="utf-8") as handle:
                        content = handle.read()
                    st.download_button("Download", content, file_name=path.name, key=f"dl_{path.name}")
            if path.suffix == ".html":
                with st.expander("Preview"):
                    st.components.v1.html(content, height=420, scrolling=True)
