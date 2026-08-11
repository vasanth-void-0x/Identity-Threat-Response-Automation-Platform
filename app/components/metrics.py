"""app/components/metrics.py - Compact KPI strip for the top of the Overview.

Sits directly below the nav bar. Each card is a single visual unit (value +
embedded sparkline) via a keyed container so the two native Streamlit
elements read as one card instead of two stacked ones - see the
`.st-key-kpi_strip` rules in app/theme.py.
"""

from __future__ import annotations

import streamlit as st

from app.components.charts import mini_sparkline_chart
from app.utils.data_mode import bucketed_counts


def render_overview_metrics(stats: dict, *, alerts: list[dict] | None = None, incidents: list[dict] | None = None) -> None:
    """Six compact KPI cards with embedded sparklines. Values are computed
    from the mode-filtered `stats`/`alerts`/`incidents` passed in by the
    caller each render, so they always reflect the currently selected data
    source - there is no caching here to go stale across a mode switch.
    """
    alerts = alerts or []
    incidents = incidents or []

    alert_trend = bucketed_counts(alerts, time_field="created_at")
    incident_trend = bucketed_counts(incidents, time_field="created_at")

    metrics = [
        ("Total Events", stats.get("total_events", 0), alert_trend, "#67e8f9"),
        ("Alerts", stats.get("total_alerts", 0), alert_trend, "#8b5cf6"),
        ("Open Incidents", stats.get("open_incidents", 0), incident_trend, "#a78bfa"),
        ("Critical", stats.get("critical_incidents", 0), incident_trend, "#fb4b5f"),
        ("High", stats.get("high_incidents", 0), incident_trend, "#fb923c"),
        ("Risk Score", stats.get("mean_risk_score", 0), incident_trend, "#fbbf24"),
    ]
    with st.container(key="kpi_strip"):
        cols = st.columns(6, gap="small")
        for col, (label, value, trend, color) in zip(cols, metrics):
            with col:
                st.metric(label, value)
                st.plotly_chart(
                    mini_sparkline_chart(trend, color=color),
                    use_container_width=True,
                    config={"displayModeBar": False, "staticPlot": True},
                    key=f"spark_{label.replace(' ', '_').lower()}",
                )


def render_severity_metrics(stats: dict) -> None:
    cols = st.columns(4)
    for col, sev in zip(cols, ["critical", "high", "medium", "low"]):
        col.metric(sev.capitalize(), stats.get(f"{sev}_incidents", 0))
