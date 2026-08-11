"""app/components/hud.py - Left/right HUD panels and the Quick Actions strip
for the Overview command centre. Pure display + safe navigation; no
component here ever mutates incident/response state directly.
"""

from __future__ import annotations

import streamlit as st

from app.utils.data_mode import latest_incident, threat_level
from app.utils.formatting import format_timestamp
from app.utils.session import navigate_to
from app.utils.status import ai_status, last_successful_sync, threat_intel_status


def _row(label: str, value: str, *, tone: str = "") -> str:
    tone_class = f" hud-{tone}" if tone else ""
    return f'<div class="hud-row"><span class="hud-label">{label}</span><span class="hud-value{tone_class}">{value}</span></div>'


def render_system_status(cfg, splunk_state: dict) -> None:
    rows = [
        _row("Splunk", splunk_state["label"].replace("SPLUNK ", "").title(),
             tone="on" if splunk_state["online"] else "off"),
        _row("Threat Intel", threat_intel_status(cfg)),
        _row("AI Analysis", ai_status(cfg)),
        _row("Response Mode", "Simulation" if cfg.response_policy.simulation_mode else "Real Actions",
             tone="on" if cfg.response_policy.simulation_mode else "warn"),
        _row("Last Sync", format_timestamp(last_successful_sync()) if last_successful_sync() else "Never"),
    ]
    st.markdown(
        '<div class="hud-card"><div class="hud-title">SYSTEM STATUS</div>' + "".join(rows) + "</div>",
        unsafe_allow_html=True,
    )


def render_live_event_monitor(event: dict | None) -> None:
    if not event:
        st.markdown(
            '<div class="hud-card"><div class="hud-title">LIVE EVENT MONITOR</div>'
            '<div class="hud-empty">No live events available</div></div>',
            unsafe_allow_html=True,
        )
        return
    ingestion_label = "Ingested (Splunk API)" if event.get("source") == "splunk_api" else "Ingested (demo replay)"
    rows = [
        _row("EventCode", str(event.get("event_code") or "—")),
        _row("Source IP", event.get("source_ip") or "—"),
        _row("User", event.get("user") or "—"),
        _row("Host", event.get("hostname") or "—"),
        _row("Timestamp", format_timestamp(event.get("timestamp"))),
        _row("Ingestion", ingestion_label, tone="on"),
    ]
    st.markdown(
        '<div class="hud-card"><div class="hud-title">LIVE EVENT MONITOR</div>' + "".join(rows) + "</div>",
        unsafe_allow_html=True,
    )


_LEVEL_TONE = {"LOW": "on", "MEDIUM": "warn", "HIGH": "warn", "CRITICAL": "off"}
_LEVEL_SEGMENTS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def render_threat_level(incidents: list[dict]) -> None:
    data = threat_level(incidents)
    level = data["level"]
    active_index = _LEVEL_SEGMENTS.index(level)
    segments = "".join(
        f'<span class="risk-seg risk-seg-{i}{" active" if i <= active_index else ""}"></span>'
        for i in range(4)
    )
    st.markdown(
        f'<div class="hud-card"><div class="hud-title">THREAT LEVEL</div>'
        f'<div class="threat-badge threat-{_LEVEL_TONE[level]}">{level}</div>'
        f'<div class="risk-bar">{segments}</div>'
        f'<div class="hud-row"><span class="hud-label">Highest score</span>'
        f'<span class="hud-value">{data["highest_score"]}/100</span></div>'
        f'<div class="hud-row"><span class="hud-label">Mean score</span>'
        f'<span class="hud-value">{data["mean_score"]}/100</span></div>'
        f'<div class="hud-row"><span class="hud-label">Critical / High</span>'
        f'<span class="hud-value">{data["critical_count"]} / {data["high_count"]}</span></div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_incident_summary(incidents: list[dict]) -> None:
    open_statuses = {"new", "investigating", "contained"}
    open_count = sum(i.get("status") in open_statuses for i in incidents)
    critical_count = sum(i.get("severity") == "critical" for i in incidents)
    latest = latest_incident(incidents)

    st.markdown('<div class="hud-card"><div class="hud-title">INCIDENT SUMMARY</div>', unsafe_allow_html=True)
    st.markdown(
        _row("Open", str(open_count)) + _row("Critical", str(critical_count)),
        unsafe_allow_html=True,
    )
    if latest:
        st.markdown(
            f'<div class="hud-latest">'
            f'<div class="hud-latest-title">{latest.get("title", "Untitled incident")}</div>'
            f'<div class="hud-latest-meta">{format_timestamp(latest.get("created_at"))} · '
            f'{latest.get("user") or "Unknown user"} · {(latest.get("source_ips") or ["—"])[0]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
        if st.button("Open incident →", key="open_latest_incident", use_container_width=True):
            st.session_state.selected_incident_id = latest["incident_id"]
            navigate_to("Incidents")
            st.rerun()
    else:
        st.markdown('<div class="hud-empty">No incidents in this data source</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def render_quick_actions(*, incidents: list[dict], mode: str) -> None:
    """Compact vertical action panel - sits below Live Event Monitor in the
    left column. Same keys/handlers as before; only the layout changed from
    a horizontal 4-column strip under the map to a stacked full-width panel.
    """
    latest = latest_incident(incidents)
    with st.container(key="quick_actions_panel"):
        st.markdown('<div class="quick-actions-label">QUICK ACTIONS</div>', unsafe_allow_html=True)
        if st.button("🔎 Investigate", use_container_width=True, key="qa_investigate",
                      help="Open the incident investigation workflow"):
            if latest:
                st.session_state.selected_incident_id = latest["incident_id"]
            navigate_to("Incidents")
            st.rerun()
        if st.button("🧭 Triage", use_container_width=True, key="qa_triage",
                      help="Open the Alerts queue for this data source"):
            navigate_to("Alerts")
            st.rerun()
        if st.button("⛓ Simulate Containment", use_container_width=True, key="qa_contain",
                      help="Open Response Center in safe simulation mode"):
            if latest and latest["incident_id"] in {i["incident_id"] for i in incidents}:
                st.session_state["_prefill_sim_incident"] = latest["incident_id"]
            navigate_to("Response")
            st.rerun()
        if st.button("📄 Export Report", use_container_width=True, key="qa_export",
                      help="Generate a PDF/HTML incident report"):
            if latest:
                st.session_state["_prefill_report_incident"] = latest["incident_id"]
            navigate_to("Reports")
            st.rerun()
