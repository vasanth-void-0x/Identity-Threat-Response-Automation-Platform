"""app/utils/session.py - Streamlit session-state helpers."""

from __future__ import annotations

import streamlit as st

from database.seed import seed_demo_data

# Single source of truth for the top-nav radio's option labels, so every
# programmatic navigation (Quick Actions, HUD click-through, header shortcuts)
# stays in sync with the widget itself instead of being silently overwritten
# by the radio's own persisted session-state value on the next rerun.
NAV_LABELS = {
    "Overview": "◉  Overview",
    "Alerts": "⚠  Alerts",
    "Incidents": "◆  Incidents",
    "Threat Intel": "◎  Threat Intel",
    "MITRE ATT&CK": "⌖  MITRE ATT&CK",
    "Response": "ϟ  Response",
    "Reports": "⎙  Reports",
    "Settings": "⚙  Settings",
}


def navigate_to(page: str) -> None:
    """Switch the active page from anywhere (Quick Actions, HUD, shortcuts).

    Only ever writes the plain `active_page` key - never the nav radio's own
    widget key directly, since Streamlit forbids writing to a widget's key
    after that widget has already rendered in the current script run (even
    right before st.rerun()). The `_nav_pending` flag tells dashboard.py to
    sync the radio's key to `active_page` at the very top of the *next* run,
    before the radio widget is (re)created - the one place that's safe to do
    it - without also clobbering the radio's own value on every ordinary
    rerun where the analyst clicked a tab manually.
    """
    st.session_state.active_page = page
    st.session_state["_nav_pending"] = True


def init_session_state() -> None:
    if "initialized" not in st.session_state:
        st.session_state.initialized = True
        st.session_state.selected_incident_id = None
        st.session_state.analyst_name = "socanalyst"
        # Demo is the safe, useful startup view. Live/Combined remain selectable
        # even while Splunk is offline so the UI never silently changes modes.
        st.session_state.data_mode = "Demo Data"
        st.session_state.active_page = "Overview"
        st.session_state.map_expanded = False


def ensure_demo_data_seeded() -> None:
    from database.repository import get_event_count
    if get_event_count() == 0:
        with st.spinner("No data found - seeding demo data..."):
            seed_demo_data(clear_first=False)
