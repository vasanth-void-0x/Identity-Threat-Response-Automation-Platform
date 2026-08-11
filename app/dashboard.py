"""Compact one-screen Streamlit shell for ITRAP."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from app.theme import app_header, inject_theme
from app.utils.data_mode import DATA_MODES
from app.utils.session import NAV_LABELS, ensure_demo_data_seeded, init_session_state
from app.utils.status import splunk_status
from app.views import (
    alerts as alerts_page,
    incident_details as incident_details_page,
    mitre_view as mitre_view_page,
    overview as overview_page,
    reports as reports_page,
    response_center as response_center_page,
    settings as settings_page,
    threat_intelligence as threat_intelligence_page,
)
from core.config import load_config
from core.logger import setup_logging

st.set_page_config(
    page_title="ITRAP — Identity Threat Response Automation Platform",
    page_icon=str(PROJECT_ROOT / "assets" / "logo" / "v-mark.svg"),
    layout="wide",
    initial_sidebar_state="collapsed",
)

cfg = load_config()
setup_logging(cfg.log_level, cfg.log_dir)
init_session_state()
ensure_demo_data_seeded()
inject_theme()

logo_svg = (PROJECT_ROOT / "assets" / "logo" / "v-mark.svg").read_text(encoding="utf-8")
logo_svg = logo_svg.replace("<svg ", '<svg class="itrap-mark" ')
selected_mode = app_header(
    logo_svg=logo_svg,
    data_mode=st.session_state.data_mode,
    data_modes=DATA_MODES,
    splunk_status=splunk_status(cfg),
    simulation=cfg.response_policy.simulation_mode,
)
if selected_mode != st.session_state.data_mode:
    st.session_state.data_mode = selected_mode
    st.rerun()

PAGES = {
    NAV_LABELS["Overview"]: overview_page,
    NAV_LABELS["Alerts"]: alerts_page,
    NAV_LABELS["Incidents"]: incident_details_page,
    NAV_LABELS["Threat Intel"]: threat_intelligence_page,
    NAV_LABELS["MITRE ATT&CK"]: mitre_view_page,
    NAV_LABELS["Response"]: response_center_page,
    NAV_LABELS["Reports"]: reports_page,
    NAV_LABELS["Settings"]: settings_page,
}

# Top navigation bar - keeps the full width free for the map/content below
# instead of a side dock competing for horizontal space. Programmatic page
# switches (Quick Actions, HUD click-through, header shortcuts) only ever
# write the plain active_page key via app.utils.session.navigate_to() plus a
# one-shot _nav_pending flag. Only when that flag is set do we sync the
# radio's own widget key from active_page, and only here, before the widget
# is (re)created this run - Streamlit forbids writing to a widget's
# session-state key after it has already rendered in the current run. This
# also means an ordinary manual click on the nav bar is never clobbered,
# since that path never sets _nav_pending.
desired_label = NAV_LABELS.get(st.session_state.active_page, NAV_LABELS["Overview"])
if st.session_state.pop("_nav_pending", False):
    st.session_state["primary_navigation"] = desired_label

radio_kwargs = dict(
    label="Modules", options=list(PAGES), horizontal=True,
    label_visibility="collapsed", key="primary_navigation",
)
if "primary_navigation" not in st.session_state:
    radio_kwargs["index"] = list(PAGES).index(desired_label)
choice = st.radio(**radio_kwargs)
st.session_state.active_page = next(name for name, label in NAV_LABELS.items() if label == choice)

PAGES[choice].render()
