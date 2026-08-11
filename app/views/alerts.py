"""Compact alert monitoring and triage workspace."""

from __future__ import annotations

import streamlit as st

from app.components.filters import alert_filters
from app.components.tables import render_alerts_table
from app.theme import page_header
from app.utils.data_mode import filter_alerts
from database import repository


def render() -> None:
    mode = st.session_state.get("data_mode", "Live Splunk")
    page_header("Alert Queue", "Search, filter and inspect prioritized detections without leaving the workspace.")
    filters = alert_filters()
    alerts = filter_alerts(repository.get_alerts(limit=1000, **filters), mode)

    table_tab, detail_tab = st.tabs([f"Alert queue · {len(alerts)}", "Alert inspector"])
    with table_tab:
        render_alerts_table(alerts, height=510)
    with detail_tab:
        options = [a["alert_id"] for a in alerts]
        selected = st.selectbox("Alert", options, index=None, placeholder="Choose an alert")
        match = next((a for a in alerts if a["alert_id"] == selected), None)
        if match:
            hero = st.columns(5)
            hero[0].metric("Severity", str(match.get("severity", "unknown")).upper())
            hero[1].metric("Score", match.get("final_score", 0))
            hero[2].metric("User", match.get("user") or "Unknown")
            hero[3].metric("Host", match.get("hostname") or "Unknown")
            hero[4].metric("Source", "Splunk" if mode == "Live Splunk" else mode)
            st.json(match, expanded=True)
        else:
            st.info("Choose an alert to inspect its full normalized evidence.")
