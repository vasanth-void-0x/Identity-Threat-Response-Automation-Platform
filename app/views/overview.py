"""One-screen SOC command centre.

Page order: Header (dashboard.py) -> Navigation (dashboard.py) -> KPI strip
-> main 3-column dashboard. There is no heading/subtitle on this page by
design - the KPI strip and HUD panels carry the context instead, which also
buys back the vertical space needed to keep everything on one screen at
1366x768 / 1920x1080.
"""

from __future__ import annotations

import streamlit as st

from app.components.charts import alert_timeline_chart, severity_donut_chart, world_attack_map_chart
from app.components.hud import (
    render_incident_summary,
    render_live_event_monitor,
    render_quick_actions,
    render_system_status,
    render_threat_level,
)
from app.components.metrics import render_overview_metrics
from app.components.tables import render_incidents_table
from app.theme import page_header
from app.utils.data_mode import filter_alerts, filter_incidents, overview_stats
from app.utils.status import splunk_status
from core.config import load_config
from database import repository

# Freed-up vertical space (no heading, no bottom KPI/Quick-Actions rows) goes
# straight into the map, which stays the visual centrepiece. Chosen to land
# close to the combined height of the left/right HUD-panel stacks so the
# map's bottom edge lines up with them rather than leaving dead space.
OVERVIEW_MAP_HEIGHT = 420


def render() -> None:
    cfg = load_config()
    mode = st.session_state.get("data_mode", "Demo Data")

    all_alerts = repository.get_alerts(limit=1000)
    all_incidents = repository.get_incidents(limit=500)
    alerts = filter_alerts(all_alerts, mode)
    incidents = filter_incidents(all_incidents, all_alerts, mode)

    if st.session_state.get("map_expanded", False):
        _render_expanded_map(alerts, mode)
        return

    # KPI strip - directly below the nav bar, always computed from the
    # current mode's filtered alerts/incidents so it updates immediately on
    # a data-source switch, same rerun as everything else on this page.
    render_overview_metrics(overview_stats(mode, alerts, incidents), alerts=alerts, incidents=incidents)

    with st.container(key="overview_main_row"):
        left_col, map_col, right_col = st.columns([1.55, 5.55, 1.9], gap="small")

        with left_col:
            render_system_status(cfg, splunk_status(cfg))
            render_live_event_monitor(repository.get_latest_event_for_mode(mode))
            render_quick_actions(incidents=incidents, mode=mode)

        with map_col:
            st.plotly_chart(
                world_attack_map_chart(alerts, height=OVERVIEW_MAP_HEIGHT),
                use_container_width=True,
                config={"displayModeBar": False, "scrollZoom": True},
                key=f"overview_map_{mode}",
            )

        with right_col:
            render_threat_level(incidents)
            render_incident_summary(incidents)
            st.plotly_chart(
                severity_donut_chart(incidents),
                use_container_width=True,
                config={"displayModeBar": False},
                key=f"overview_donut_{mode}",
            )

    source_label = "Live public-IP lookups" if cfg.threat_intelligence.geoip_provider == "live" else "Simulated GeoIP locations"
    with st.container(key="overview_footer_row"):
        footer_geo, footer_sync, footer_map, footer_trend, footer_recent = st.columns(
            [1.95, 1.4, .75, 1.05, 1.3], vertical_alignment="center"
        )
        with footer_geo:
            st.caption(f"GeoIP · {source_label} · hover for evidence")
        with footer_sync:
            sync = repository.get_splunk_sync_state() or {}
            st.caption(f"Last sync · {sync.get('events_ingested', 0)} ingested / {sync.get('events_retrieved', 0)} retrieved")
        with footer_map:
            if st.button("⛶ Full map", use_container_width=True, key="open_fullscreen_map"):
                st.session_state.map_expanded = True
                st.rerun()
        with footer_trend:
            with st.popover("📈 Alert volume", use_container_width=True):
                st.plotly_chart(
                    alert_timeline_chart(alerts), use_container_width=True,
                    config={"displayModeBar": False}, key=f"overview_timeline_{mode}",
                )
        with footer_recent:
            with st.popover(f"Recent incidents · {len(incidents)}", use_container_width=True):
                render_incidents_table(incidents[:15])


def _render_expanded_map(alerts: list[dict], mode: str) -> None:
    st.markdown('<div class="map-fullscreen-shell"></div>', unsafe_allow_html=True)
    title_col, back_col = st.columns([6, 1], vertical_alignment="center")
    with title_col:
        page_header("Global Source Intelligence", f"Expanded GeoIP evidence view · {mode}")
    with back_col:
        if st.button("← Overview", use_container_width=True, key="close_fullscreen_map"):
            st.session_state.map_expanded = False
            st.rerun()
    st.plotly_chart(
        world_attack_map_chart(alerts, expanded=True),
        use_container_width=True,
        config={"displayModeBar": True, "scrollZoom": True, "displaylogo": False},
        key=f"fullscreen_map_{mode}",
    )
    st.caption("Hover a source to inspect location, IPs, users, devices, severity, provider and alert volume. Scroll to zoom; drag to pan.")
