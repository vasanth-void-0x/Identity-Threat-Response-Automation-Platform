"""Incident queue and tabbed investigation workspace."""

from __future__ import annotations

import streamlit as st

from app.components.filters import incident_filters
from app.components.incident_panel import render_incident_panel
from app.components.tables import render_incidents_table
from app.theme import page_header
from app.utils.data_mode import filter_incidents
from database import repository


def render() -> None:
    mode = st.session_state.get("data_mode", "Live Splunk")
    page_header("Incident Investigation", "Correlated evidence, analyst decisions and reports in a tabbed case workspace.")
    filters = incident_filters()
    all_alerts = repository.get_alerts(limit=5000)
    incidents = filter_incidents(repository.get_incidents(limit=500, **filters), all_alerts, mode)

    incident_ids = [item["incident_id"] for item in incidents]

    pending = st.session_state.pop("selected_incident_id", None)
    if pending and pending in incident_ids and st.session_state.get("active_case_select") != pending:
        st.session_state["active_case_select"] = pending

    selected = st.selectbox(
        "Active case", incident_ids, index=None, placeholder="Choose an incident to investigate",
        key="active_case_select",
    )
    if selected:
        render_incident_panel(selected)
    else:
        render_incidents_table(incidents, height=505)
