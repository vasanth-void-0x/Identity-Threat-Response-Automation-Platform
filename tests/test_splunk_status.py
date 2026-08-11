"""Regression coverage for app/utils/status.py - Splunk connectivity must
never be inferred from configuration values alone."""

from types import SimpleNamespace
from unittest.mock import patch

import streamlit as st

from app.utils.status import splunk_status


def _cfg(is_configured: bool) -> SimpleNamespace:
    return SimpleNamespace(splunk_api=SimpleNamespace(is_configured=is_configured))


def test_unconfigured_splunk_is_always_offline_no_network_call():
    st.session_state.clear()
    result = splunk_status(_cfg(False))
    assert result["online"] is False
    assert result["label"] == "SPLUNK OFFLINE"


def test_configured_but_never_tested_is_offline_not_online():
    """Configuration presence alone must never be treated as proof of connectivity."""
    st.session_state.clear()
    with patch("app.utils.status.repository.get_splunk_sync_state", return_value=None):
        result = splunk_status(_cfg(True))
    assert result["online"] is False
    assert "not yet verified" in result["detail"].lower()


def test_successful_explicit_test_marks_online():
    st.session_state.clear()
    st.session_state["splunk_last_test"] = {"connected": True, "version": "9.1.0"}
    result = splunk_status(_cfg(True))
    assert result["online"] is True
    assert result["label"] == "SPLUNK ONLINE"


def test_failed_explicit_test_marks_offline_with_reason():
    st.session_state.clear()
    st.session_state["splunk_last_test"] = {"connected": False, "error": "timed out"}
    result = splunk_status(_cfg(True))
    assert result["online"] is False
    assert "timed out" in result["detail"]


def test_successful_past_sync_counts_as_verified_connectivity():
    st.session_state.clear()
    with patch("app.utils.status.repository.get_splunk_sync_state",
               return_value={"last_sync_result": "success"}):
        result = splunk_status(_cfg(True))
    assert result["online"] is True
