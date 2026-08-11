"""app/utils/status.py - Accurate, non-spamming integration status for the HUD.

Splunk connectivity in particular must never be inferred from configuration
values alone (a token being present in `.env` is not proof anything is
reachable). Status here is only ever "online" once an explicit connection
test or a successful sync has actually happened - both analyst-triggered
from Settings, never polled automatically on every rerun.
"""

from __future__ import annotations

import streamlit as st

from core.config import AppConfig
from database import repository


def splunk_status(cfg: AppConfig) -> dict:
    """Real Splunk connectivity status for header/HUD display.

    Returns a dict with: online (bool), label (str), detail (str).
    """
    scfg = cfg.splunk_api
    if not scfg.is_configured:
        return {"online": False, "label": "SPLUNK OFFLINE", "detail": "Not configured"}

    tested = st.session_state.get("splunk_last_test")
    if tested and tested.get("connected"):
        version = tested.get("version") or ""
        return {"online": True, "label": "SPLUNK ONLINE", "detail": f"v{version}" if version else "Connected"}

    sync_state = repository.get_splunk_sync_state()
    if sync_state and sync_state.get("last_sync_result") == "success":
        return {"online": True, "label": "SPLUNK ONLINE", "detail": "Verified by last sync"}

    if tested and tested.get("connected") is False:
        return {"online": False, "label": "SPLUNK OFFLINE", "detail": tested.get("error") or "Connection failed"}

    return {"online": False, "label": "SPLUNK OFFLINE", "detail": "Configured but not yet verified - test in Settings"}


def threat_intel_status(cfg: AppConfig) -> str:
    ti = cfg.threat_intelligence
    if ti.provider == "mock":
        return "Mock"
    return "Connected" if (ti.virustotal_api_key or ti.abuseipdb_api_key) else "Mock fallback"


def ai_status(cfg: AppConfig) -> str:
    if cfg.ai.provider == "mock":
        return "Mock"
    return "Connected" if cfg.ai.groq_api_key else "Mock fallback"


def last_successful_sync() -> str | None:
    """Most recent successful sync timestamp across Splunk/Wazuh, or None."""
    candidates = []
    for state in (repository.get_splunk_sync_state(), repository.get_wazuh_sync_state()):
        if state and state.get("last_sync_result") == "success" and state.get("last_sync_at"):
            candidates.append(state["last_sync_at"])
    return max(candidates) if candidates else None
