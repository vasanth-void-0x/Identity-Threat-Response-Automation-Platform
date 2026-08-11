"""app/components/filters.py - Reusable sidebar/inline filter widgets."""

from __future__ import annotations

import streamlit as st


def alert_filters() -> dict:
    col1, col2, col3 = st.columns(3)
    with col1:
        severity = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
    with col2:
        status = st.selectbox("Status", ["All", "new", "triaged", "investigating", "contained", "resolved", "false_positive"])
    with col3:
        user = st.text_input("User (exact match)")

    filters = {}
    if severity != "All":
        filters["severity"] = severity
    if status != "All":
        filters["status"] = status
    if user:
        filters["user"] = user
    return filters


def incident_filters() -> dict:
    col1, col2 = st.columns(2)
    with col1:
        severity = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"], key="inc_sev")
    with col2:
        status = st.selectbox(
            "Status", ["All", "new", "triaged", "investigating", "contained", "resolved", "false_positive"],
            key="inc_status",
        )
    filters = {}
    if severity != "All":
        filters["severity"] = severity
    if status != "All":
        filters["status"] = status
    return filters
