"""Streamlit AppTest coverage for the rebuilt Overview command centre:
top navigation, all three data modes, Quick Actions deep-links, and the
empty/offline state when Live Splunk has no ingested evidence yet.
"""

from pathlib import Path

from streamlit.testing.v1 import AppTest

DASHBOARD_PATH = Path(__file__).resolve().parent.parent / "app" / "dashboard.py"

NAV_LABELS = [
    "\u25c9  Overview", "\u26a0  Alerts", "\u25c6  Incidents", "\u25ce  Threat Intel",
    "\u2316  MITRE ATT&CK", "\u03df  Response", "\u2399  Reports", "\u2699  Settings",
]


def _run() -> AppTest:
    at = AppTest.from_file(str(DASHBOARD_PATH), default_timeout=90)
    at.run()
    return at


def test_overview_renders_with_no_exceptions_on_default_demo_mode():
    at = _run()
    assert not at.exception
    assert at.session_state["data_mode"] == "Demo Data"


def test_every_nav_page_renders_with_no_exceptions():
    at = _run()
    for label in NAV_LABELS:
        at.radio(key="primary_navigation").set_value(label).run()
        assert not at.exception, f"{label} raised: {at.exception}"


def test_all_three_data_modes_render_with_no_exceptions():
    at = _run()
    for mode in ("Live Splunk", "Combined", "Demo Data"):
        at.segmented_control(key="header_mode").set_value(mode).run()
        assert not at.exception, f"{mode} raised: {at.exception}"
        assert at.session_state["data_mode"] == mode


def test_live_splunk_mode_shows_empty_and_offline_states_not_fabricated_data():
    at = _run()
    at.segmented_control(key="header_mode").set_value("Live Splunk").run()
    assert not at.exception
    combined_markdown = " ".join(m.value for m in at.markdown)
    assert "No live events available" in combined_markdown
    assert "No incidents in this data source" in combined_markdown
    assert "SPLUNK OFFLINE" in combined_markdown


def test_full_map_open_and_back():
    at = _run()
    at.button(key="open_fullscreen_map").click().run()
    assert not at.exception
    assert at.session_state["map_expanded"] is True
    at.button(key="close_fullscreen_map").click().run()
    assert not at.exception
    assert at.session_state["map_expanded"] is False


def test_quick_action_investigate_navigates_to_incidents_with_incident_preselected():
    at = _run()
    at.button(key="qa_investigate").click().run()
    assert not at.exception
    assert at.session_state["active_page"] == "Incidents"
    assert at.session_state["active_case_select"]


def test_quick_action_triage_navigates_to_alerts():
    at = _run()
    at.button(key="qa_triage").click().run()
    assert not at.exception
    assert at.session_state["active_page"] == "Alerts"


def test_quick_action_simulate_containment_navigates_to_response_with_prefill():
    at = _run()
    at.button(key="qa_contain").click().run()
    assert not at.exception
    assert at.session_state["active_page"] == "Response"
    assert at.session_state["sim_incident"] != "-- select --"


def test_quick_action_export_report_navigates_to_reports_with_prefill():
    at = _run()
    at.button(key="qa_export").click().run()
    assert not at.exception
    assert at.session_state["active_page"] == "Reports"
    assert at.session_state["report_incident_select"]


def test_manual_nav_click_is_never_overridden_by_prior_navigation():
    """Regression test for the v1.3.5 nav-radio/session-state fight: a manual
    tab click must always win, even right after a Quick Action redirect."""
    at = _run()
    at.button(key="qa_triage").click().run()
    assert at.session_state["active_page"] == "Alerts"
    at.radio(key="primary_navigation").set_value("\u2699  Settings").run()
    assert not at.exception
    assert at.session_state["active_page"] == "Settings"
