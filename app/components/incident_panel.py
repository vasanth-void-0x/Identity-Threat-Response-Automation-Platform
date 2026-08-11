"""app/components/incident_panel.py - Detailed incident view panel, reused across pages."""

from __future__ import annotations

import streamlit as st

from ai_engine.incident_summary import generate_incident_summary
from ai_engine.recommendations import build_containment_recommendations, build_investigation_checklist
from app.components.charts import risk_score_gauge
from app.utils.formatting import format_timestamp, severity_badge
from app.utils.session import navigate_to
from database import repository
from models.incident import Incident
from mitre.mapper import map_techniques
from reports.report_builder import build_incident_report


def render_incident_panel(incident_id: str) -> None:
    incident = repository.get_incident(incident_id)
    if not incident:
        st.error(f"Incident {incident_id} not found.")
        return

    st.markdown(f"## {incident['title']}")
    st.markdown(severity_badge(incident["severity"]))

    hero = st.columns(5)
    hero[0].metric("Risk", f"{incident['risk_score']}/100")
    hero[1].metric("Status", str(incident["status"]).replace("_", " ").title())
    hero[2].metric("User", incident.get("user") or "Unknown")
    hero[3].metric("Hosts", len(incident.get("hosts", [])))
    hero[4].metric("Techniques", len(incident.get("mitre_techniques", [])))

    shortcut_col, _spacer = st.columns([1.4, 4.6])
    with shortcut_col:
        if st.button("📄 Export Report", key=f"shortcut_export_{incident_id}", use_container_width=True,
                      help="Jump to the Reports page with this incident preselected"):
            st.session_state["_prefill_report_incident"] = incident_id
            navigate_to("Reports")
            st.rerun()

    overview_tab, timeline_tab, mitre_tab, ai_tab, investigation_tab, actions_tab, report_tab = st.tabs(
        ["Summary", "Timeline", "MITRE", "AI Analysis", "Investigation", "Notes & Actions", "Report"]
    )

    with overview_tab:
        col1, col2 = st.columns([1.8, 1])
        with col1:
            st.write(f"**Incident ID** · `{incident['incident_id']}`")
            st.write(f"**Affected identity** · {incident.get('user') or 'Unknown account'}")
            st.write(f"**Source IPs** · {', '.join(incident.get('source_ips', [])) or 'Not available'}")
            st.write(f"**Assets** · {', '.join(incident.get('hosts', [])) or 'Not available'}")
            st.write(f"**Created** · {format_timestamp(incident['created_at'])}")
            st.write(f"**Updated** · {format_timestamp(incident['updated_at'])}")
        with col2:
            st.plotly_chart(risk_score_gauge(incident["risk_score"], incident["severity"]), use_container_width=True, config={"displayModeBar": False})

    with timeline_tab:
        for index, entry in enumerate(incident.get("timeline", []), start=1):
            st.markdown(f"**{index:02d}** · `{format_timestamp(entry.get('timestamp', ''))}` · {entry.get('description', '')}")

    with mitre_tab:
        mitre_details = map_techniques(incident.get("mitre_techniques", []))
        for technique in mitre_details:
            with st.expander(f"{technique['id']} · {technique['name']} · {technique['tactic']}"):
                st.write(technique["description"])
                for step in technique.get("investigation_steps", []):
                    st.write(f"- {step}")

    with ai_tab:
        st.caption("AI output is advisory and never triggers a response action.")
        st.info(incident.get("ai_summary") or "No AI analysis generated for this case yet.")
        if st.button("Generate AI analysis", key=f"ai_{incident_id}"):
            alerts = repository.get_alerts(limit=1000)
            related_titles = [a["title"] for a in alerts if a.get("incident_id") == incident_id]
            incident_obj = Incident(**{k: v for k, v in incident.items() if k in Incident.model_fields})
            repository.set_ai_summary(incident_id, generate_incident_summary(incident_obj, related_titles))
            st.rerun()

    with investigation_tab:
        left, right = st.columns(2)
        with left:
            st.markdown("### Investigation checklist")
            for item in build_investigation_checklist(incident.get("mitre_techniques", [])):
                st.checkbox(item, key=f"check_{incident_id}_{hash(item)}")
        with right:
            st.markdown("### Recommended containment")
            st.caption("Analyst review only")
            for rec in build_containment_recommendations(incident["severity"]):
                st.write(f"- {rec}")

    with actions_tab:
      if incident.get("user") and (incident.get("source_ips") or incident.get("hosts")):
        st.markdown("### Trusted baseline review")
        st.warning("Trust only after investigation. Trusted values suppress future new-IP/device alerts.")
        actor = st.text_input("Analyst name", key=f"trust_actor_{incident_id}")
        reason = st.text_input("Trust reason", key=f"trust_reason_{incident_id}")
        c1, c2 = st.columns(2)
        with c1:
            ip_options = incident.get("source_ips", [])
            selected_ip = st.selectbox("Source IP", ip_options or ["N/A"], key=f"trust_ip_select_{incident_id}")
            if st.button("Trust IP", key=f"trust_ip_{incident_id}", disabled=not ip_options):
                try:
                    repository.add_trusted_ip(incident["user"], selected_ip, actor, reason)
                    st.success("IP trusted and audit logged.")
                except ValueError as exc:
                    st.error(str(exc))
        with c2:
            host_options = incident.get("hosts", [])
            selected_host = st.selectbox("Device / host", host_options or ["N/A"], key=f"trust_device_select_{incident_id}")
            if st.button("Trust Device", key=f"trust_device_{incident_id}", disabled=not host_options):
                try:
                    repository.add_trusted_device(incident["user"], selected_host, actor, reason)
                    st.success("Device trusted and audit logged.")
                except ValueError as exc:
                    st.error(str(exc))

      st.markdown("### Analyst notes")
      for note in incident.get("investigation_notes", []):
          st.write(f"- {note}")
      new_note = st.text_input("Add a note", key=f"note_input_{incident_id}")
      if st.button("Add note", key=f"note_btn_{incident_id}") and new_note:
          repository.add_investigation_note(incident_id, new_note, author=st.session_state.get("analyst_name", "analyst"))
          st.rerun()
      col_a, col_b, col_c = st.columns(3)
      with col_a:
          if st.button("Mark contained", key=f"contain_{incident_id}"):
              repository.update_incident_status(incident_id, "contained", actor=st.session_state.get("analyst_name", "analyst")); st.rerun()
      with col_b:
          if st.button("Mark resolved", key=f"resolve_{incident_id}"):
              repository.update_incident_status(incident_id, "resolved", actor=st.session_state.get("analyst_name", "analyst")); st.rerun()
      with col_c:
          if st.button("Mark false positive", key=f"fp_{incident_id}"):
              repository.mark_false_positive(incident_id, actor=st.session_state.get("analyst_name", "analyst")); st.rerun()

    with report_tab:
        st.caption("Reports include the incident timeline, ATT&CK mapping, AI analysis and analyst notes.")
        pdf_col, html_col = st.columns(2)
        with pdf_col:
            if st.button("Build PDF report", key=f"pdf_{incident_id}"):
                path = build_incident_report(incident_id, fmt="pdf")
                with open(path, "rb") as handle:
                    st.download_button("Download PDF", handle, file_name=f"{incident_id}_report.pdf")
        with html_col:
            if st.button("Build HTML report", key=f"html_{incident_id}"):
                path = build_incident_report(incident_id, fmt="html")
                with open(path, "r", encoding="utf-8") as handle:
                    st.download_button("Download HTML", handle.read(), file_name=f"{incident_id}_report.html")
