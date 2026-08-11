"""app/views/settings.py - Application settings and status page (no secrets exposed)."""

from __future__ import annotations

import streamlit as st

from app.theme import page_header
from app.utils.formatting import format_timestamp
from core.config import load_config
from database import repository
from integrations.wazuh_api_client import WazuhAPIClient, sync_wazuh_events
from integrations.splunk_api_client import SplunkAPIClient, sync_splunk_events

APP_VERSION = "1.5.0"


def render() -> None:
    cfg = load_config()
    page_header("Platform Settings", "Integration health, policy guardrails and runtime configuration without exposing secrets.")
    general_tab, splunk_tab, intel_tab, ai_tab, response_tab, baseline_tab, wazuh_tab = st.tabs(
        ["General", "Splunk", "Threat Intel", "AI", "Response", "Baselines", "Wazuh"]
    )
    with general_tab:
        c1, c2, c3 = st.columns(3)
        c1.metric("Version", APP_VERSION)
        c2.metric("Environment", cfg.environment)
        c3.metric("Log level", cfg.log_level)
        st.write(f"**Application** · {cfg.app_name}")
        st.write(f"**Database path** · `{cfg.database_path}`")
        st.info("Secret values are configured through `.env` and are never rendered in this interface.")
    with splunk_tab:
        _render_splunk_section(cfg)
    with intel_tab:
        st.write(f"**Provider** · {cfg.threat_intelligence.provider}")
        st.write(f"**API key** · {'Configured' if (cfg.threat_intelligence.virustotal_api_key or cfg.threat_intelligence.abuseipdb_api_key) else 'Mock fallback'}")
        st.write(f"**GeoIP provider** · {cfg.threat_intelligence.geoip_provider}")
    with ai_tab:
        st.write(f"**Configured provider** · {cfg.ai.provider}")
        st.write(f"**Runtime readiness** · {'API key configured' if cfg.ai.groq_api_key else 'Deterministic fallback'}")
        st.caption("The incident workspace identifies AI output as advisory; it never triggers response actions.")
    with response_tab:
        st.write(f"**Simulation mode** · {'Enabled (safe default)' if cfg.response_policy.simulation_mode else 'Disabled'}")
        st.write(f"**Analyst approval** · {cfg.response_policy.require_analyst_approval}")
        st.write(f"**Minimum severity** · {cfg.response_policy.minimum_severity_threshold}")
        st.write(f"**Protected users** · {', '.join(cfg.response_policy.protected_users)}")
        st.write(f"**Protected hosts** · {', '.join(cfg.response_policy.protected_hosts) or 'none'}")
    with baseline_tab:
        st.write(f"**Correlation window** · {cfg.correlation_window_minutes} minutes")
        _render_trusted_baselines()
    with wazuh_tab:
        _render_wazuh_section(cfg)


def _render_wazuh_section(cfg) -> None:
    st.subheader("🔗 Wazuh Integration (Experimental)")
    st.warning(
        "Live API ingestion has not been validated against a real Wazuh Manager/Indexer. "
        "Use the supported Wazuh alerts.json export adapter for reliable offline demos."
    )

    wazuh_cfg = cfg.wazuh_api
    is_configured = wazuh_cfg.is_configured

    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Configuration status:** {'✅ Configured' if is_configured else '❌ Not configured'}")
        st.write(f"**API URL:** `{wazuh_cfg.api_url or '(not set)'}`")
        st.write(f"**SSL verification:** {'✅ Enabled' if wazuh_cfg.verify_ssl else '⚠️ Disabled'}")
    with col2:
        sync_state = repository.get_wazuh_sync_state()
        if sync_state and sync_state.get("last_sync_at"):
            st.write(f"**Last sync:** {format_timestamp(sync_state['last_sync_at'])}")
            result_icon = "✅" if sync_state.get("last_sync_result") == "success" else "❌"
            st.write(f"**Last sync result:** {result_icon} {sync_state.get('last_sync_result', 'unknown')}")
            if sync_state.get("last_sync_error"):
                st.write(f"**Last error:** {sync_state['last_sync_error']}")
            st.write(f"**Events retrieved / ingested:** {sync_state.get('events_retrieved', 0)} / "
                     f"{sync_state.get('events_ingested', 0)}")
            st.write(f"**Alerts / incidents generated:** {sync_state.get('alerts_generated', 0)} / "
                     f"{sync_state.get('incidents_generated', 0)}")
        else:
            st.write("**Last sync:** never")

    if not is_configured:
        st.caption(
            "Set `WAZUH_API_URL`, `WAZUH_API_USERNAME`, `WAZUH_API_PASSWORD` in `.env` to enable. "
            "The platform continues to work fully in offline demo mode without this."
        )
        return

    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        if st.button("🔌 Test Connection"):
            with st.spinner("Testing Wazuh API connection..."):
                client = WazuhAPIClient()
                status = client.test_connection()
            if status["connected"]:
                st.success("✅ Connected - authentication succeeded.")
            else:
                st.error(f"❌ Connection failed: {status['error']}")

    with btn_col2:
        if st.button("🔄 Sync Wazuh Events"):
            with st.spinner("Syncing events from Wazuh API..."):
                result = sync_wazuh_events(hours_back=24, max_events=500)
            if result["success"]:
                st.success(
                    f"✅ Sync complete - {result['events_retrieved']} retrieved, "
                    f"{result['events_ingested']} new events ingested, "
                    f"{result['alerts_generated']} alert(s), {result['incidents_generated']} incident(s)."
                )
                st.rerun()
            else:
                st.error(f"❌ Sync failed: {result['error']}")

    st.caption(
        "Real API calls only happen when you click these buttons - there is no automatic "
        "background polling."
    )


def _render_splunk_section(cfg) -> None:
    st.subheader("🟢 Splunk Enterprise Integration")
    scfg = cfg.splunk_api
    c1, c2 = st.columns(2)
    with c1:
        st.write(f"**Configuration:** {'✅ Configured' if scfg.is_configured else '❌ Token not configured'}")
        st.write(f"**Management API:** `{scfg.url}`")
        st.write(f"**Index:** `{scfg.index}`")
        st.write(f"**Sourcetype:** `{scfg.sourcetype}`")
        st.write(f"**SSL verification:** {'✅ Enabled' if scfg.verify_ssl else '⚠️ Disabled (localhost lab only)'}")
    with c2:
        state = repository.get_splunk_sync_state()
        if state:
            st.write(f"**Last sync:** {format_timestamp(state.get('last_sync_at', ''))}")
            st.write(f"**Result:** {state.get('last_sync_result', 'unknown')}")
            st.write(f"**Retrieved / ingested:** {state.get('events_retrieved', 0)} / {state.get('events_ingested', 0)}")
            st.write(f"**Alerts / incidents:** {state.get('alerts_generated', 0)} / {state.get('incidents_generated', 0)}")
            if state.get("last_sync_error"):
                st.error(state["last_sync_error"])
        else:
            st.write("**Last sync:** never")

    if not scfg.is_configured:
        st.info("Copy `.env.example` to `.env`, add your Splunk token, then restart ITRAP. The token is never displayed.")
        return
    b1, b2 = st.columns(2)
    with b1:
        if st.button("🔌 Test Splunk Connection"):
            with st.spinner("Connecting to Splunk..."):
                status = SplunkAPIClient().test_connection()
            # Cached so the header/HUD status pill reflects a real, analyst-triggered
            # test instead of polling Splunk on every rerun. Never treated as proof
            # of connectivity until this test (or a successful sync) actually runs.
            st.session_state["splunk_last_test"] = status
            if status.get("connected"):
                st.success(f"✅ Connected to Splunk {status.get('version', 'unknown')}")
            else:
                st.error(f"❌ {status.get('error')}")
    with b2:
        if st.button("🔄 Sync Splunk Events"):
            with st.spinner("Retrieving relevant Windows events from Splunk..."):
                result = sync_splunk_events(earliest="-15m", max_events=scfg.max_events)
            if result.get("success"):
                st.success(
                    f"✅ {result['events_retrieved']} retrieved, {result['events_ingested']} new, "
                    f"{result['alerts_generated']} alerts, {result['incidents_generated']} incidents"
                )
                st.rerun()
            else:
                st.error(f"❌ {result.get('error')}")
    st.caption("Sync is manual and bounded to relevant Windows Security EventCodes; no background polling is used.")


def _render_trusted_baselines() -> None:
    st.subheader("🛡️ Trusted IP / Device Baselines")
    st.caption("Only explicit analyst actions change this list. Detection never auto-trusts observed values.")
    baselines = repository.get_trusted_baselines()
    rows = [
        {"user": user, "trusted_ips": ", ".join(v["ips"]), "trusted_devices": ", ".join(v["devices"])}
        for user, v in baselines.items()
    ]
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No trusted baselines configured.")

    with st.expander("Manage trusted baseline"):
        analyst = st.text_input("Analyst name", key="baseline_actor")
        username = st.text_input("Username", key="baseline_user")
        value_type = st.selectbox("Value type", ["IP address", "Device / hostname"])
        value = st.text_input("IP or device value", key="baseline_value")
        reason = st.text_input("Reason (required when trusting)", key="baseline_reason")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Trust value"):
                try:
                    if value_type == "IP address":
                        repository.add_trusted_ip(username, value, analyst, reason)
                    else:
                        repository.add_trusted_device(username, value, analyst, reason)
                    st.success("Trusted baseline updated and audit logged.")
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
        with col2:
            confirm = st.checkbox("Confirm removal", key="baseline_remove_confirm")
            if st.button("Remove value"):
                if not confirm:
                    st.error("Confirm removal first.")
                else:
                    try:
                        if value_type == "IP address":
                            repository.remove_trusted_ip(username, value, analyst)
                        else:
                            repository.remove_trusted_device(username, value, analyst)
                        st.warning("Trusted baseline removed and audit logged.")
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
