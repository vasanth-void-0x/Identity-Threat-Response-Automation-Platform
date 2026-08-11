"""app/components/tables.py - Reusable dataframe table renderers."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app.utils.formatting import SEVERITY_EMOJI, format_timestamp


def render_incidents_table(incidents: list[dict], *, height: int = 310) -> None:
    if not incidents:
        st.info("No incidents to display.")
        return
    df = pd.DataFrame(incidents)
    df["severity_label"] = df["severity"].map(SEVERITY_EMOJI).fillna("⚪") + " " + df["severity"].str.upper()
    df["created_at"] = df["created_at"].apply(format_timestamp)
    # Most important columns first, per dashboard readability requirements -
    # severity, incident ID, title, risk score, status, user, created time.
    df = df.rename(columns={"severity_label": "severity", "severity": "_severity_raw",
                             "risk_score": "risk score", "created_at": "created time"})
    ordered_cols = ["severity", "incident_id", "title", "risk score", "status", "user", "created time"]
    st.dataframe(df[ordered_cols], use_container_width=True, hide_index=True, height=height)


def render_alerts_table(alerts: list[dict], *, height: int = 430) -> None:
    if not alerts:
        st.info("No alerts to display.")
        return
    df = pd.DataFrame(alerts)
    df["severity_label"] = df["severity"].map(SEVERITY_EMOJI).fillna("⚪") + " " + df["severity"].str.upper()
    df["created_at"] = df["created_at"].apply(format_timestamp)
    df = df.rename(columns={"severity_label": "severity", "severity": "_severity_raw",
                             "final_score": "score", "created_at": "created time"})
    ordered_cols = ["severity", "alert_id", "rule_name", "title", "score", "user", "source_ip", "hostname", "created time"]
    st.dataframe(df[ordered_cols], use_container_width=True, hide_index=True, height=height)


def render_response_actions_table(actions: list[dict], *, height: int = 390) -> None:
    if not actions:
        st.info("No response actions recorded yet.")
        return
    df = pd.DataFrame(actions)
    for col in ("approved_by", "approved_at", "rejected_by", "executed_at"):
        if col not in df.columns:
            df[col] = None
    df["timestamp"] = df["timestamp"].apply(format_timestamp)
    df["approved_at"] = df["approved_at"].apply(lambda v: format_timestamp(v) if isinstance(v, str) else "")
    df["executed_at"] = df["executed_at"].apply(lambda v: format_timestamp(v) if isinstance(v, str) else "")
    df = df.rename(columns={
        "action_type": "action", "requested_by": "requester", "approved_by": "approver",
        "approved_at": "approved at", "mode": "execution mode", "timestamp": "requested at",
        "executed_at": "executed at",
    })
    ordered_cols = ["action", "target", "status", "requester", "approver", "approved at",
                    "execution mode", "result", "requested at", "executed at"]
    st.dataframe(df[ordered_cols], use_container_width=True, hide_index=True, height=height)
