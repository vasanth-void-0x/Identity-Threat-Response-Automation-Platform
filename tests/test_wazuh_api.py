"""
tests/test_wazuh_api.py
Tests for the Wazuh REST API client: authentication success/failure,
pagination, timeouts, malformed responses, event conversion, and duplicate
prevention. All HTTP calls are mocked via `requests_mock`-style patching -
no real network access or Wazuh credentials are required or used.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from core.config import WazuhAPIConfig
from database import repository
from integrations.wazuh_api_client import (
    WazuhAPIClient,
    WazuhAPIError,
    WazuhAuthenticationError,
    event_fingerprint,
    sync_wazuh_events,
    wazuh_alert_to_raw_event,
)

CFG = WazuhAPIConfig(
    api_url="https://wazuh.example.lab:55000",
    username="wazuh_wui",
    password="not-a-real-password",
    verify_ssl=True,
    request_timeout_seconds=5,
)


def _mock_response(status_code=200, json_data=None, raise_json_error=False):
    resp = MagicMock()
    resp.status_code = status_code
    if raise_json_error:
        resp.json.side_effect = ValueError("not json")
    else:
        resp.json.return_value = json_data or {}
    return resp


# --- Authentication ----------------------------------------------------------------
def test_authenticate_success():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", return_value=_mock_response(200, {"data": {"token": "fake.jwt.token"}})):
        token = client.authenticate()
    assert token == "fake.jwt.token"


def test_authenticate_invalid_credentials_raises():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", return_value=_mock_response(401)):
        with pytest.raises(WazuhAuthenticationError):
            client.authenticate()


def test_authenticate_forbidden_raises():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", return_value=_mock_response(403)):
        with pytest.raises(WazuhAuthenticationError):
            client.authenticate()


def test_authenticate_missing_token_in_response_raises():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", return_value=_mock_response(200, {"data": {}})):
        with pytest.raises(WazuhAPIError):
            client.authenticate()


def test_authenticate_connection_error_raises_clear_message():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError()):
        with pytest.raises(WazuhAPIError, match="connect"):
            client.authenticate()


def test_authenticate_timeout_raises_clear_message():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", side_effect=requests.exceptions.Timeout()):
        with pytest.raises(WazuhAPIError, match="timed out"):
            client.authenticate()


def test_authenticate_malformed_json_raises():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", return_value=_mock_response(200, raise_json_error=True)):
        with pytest.raises(WazuhAPIError):
            client.authenticate()


def test_not_configured_client_raises_before_any_request():
    client = WazuhAPIClient(WazuhAPIConfig())  # all fields blank
    assert client.is_configured is False
    with pytest.raises(WazuhAPIError, match="not configured"):
        client.authenticate()


def test_test_connection_never_raises_on_failure():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", return_value=_mock_response(401)):
        status = client.test_connection()
    assert status["connected"] is False
    assert "Authentication failed" in status["error"]


def test_test_connection_reports_success():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", return_value=_mock_response(200, {"data": {"token": "abc"}})):
        status = client.test_connection()
    assert status["connected"] is True
    assert status["error"] is None


# --- Pagination / alert retrieval ---------------------------------------------------
def test_get_alerts_single_page():
    client = WazuhAPIClient(CFG)
    page = {"data": {"affected_items": [{"id": "1"}, {"id": "2"}]}}
    with patch("requests.post", return_value=_mock_response(200, {"data": {"token": "t"}})), \
         patch("requests.get", return_value=_mock_response(200, page)):
        alerts = client.get_alerts(hours_back=24, max_events=100, page_size=50)
    assert len(alerts) == 2


def test_get_alerts_paginates_across_multiple_pages():
    client = WazuhAPIClient(CFG)
    page1 = {"data": {"affected_items": [{"id": str(i)} for i in range(50)]}}
    page2 = {"data": {"affected_items": [{"id": str(i)} for i in range(50, 75)]}}

    call_count = {"n": 0}

    def fake_get(*args, **kwargs):
        call_count["n"] += 1
        return _mock_response(200, page1 if call_count["n"] == 1 else page2)

    with patch("requests.post", return_value=_mock_response(200, {"data": {"token": "t"}})), \
         patch("requests.get", side_effect=fake_get):
        alerts = client.get_alerts(hours_back=24, max_events=200, page_size=50)

    assert len(alerts) == 75  # last page was partial -> pagination stopped correctly


def test_get_alerts_respects_max_events_cap():
    client = WazuhAPIClient(CFG)
    big_page = {"data": {"affected_items": [{"id": str(i)} for i in range(50)]}}
    with patch("requests.post", return_value=_mock_response(200, {"data": {"token": "t"}})), \
         patch("requests.get", return_value=_mock_response(200, big_page)):
        alerts = client.get_alerts(hours_back=24, max_events=30, page_size=50)
    assert len(alerts) == 30


def test_get_alerts_timeout_raises():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", return_value=_mock_response(200, {"data": {"token": "t"}})), \
         patch("requests.get", side_effect=requests.exceptions.Timeout()):
        with pytest.raises(WazuhAPIError, match="timed out"):
            client.get_alerts()


def test_get_alerts_malformed_response_raises():
    client = WazuhAPIClient(CFG)
    with patch("requests.post", return_value=_mock_response(200, {"data": {"token": "t"}})), \
         patch("requests.get", return_value=_mock_response(200, raise_json_error=True)):
        with pytest.raises(WazuhAPIError):
            client.get_alerts()


def test_get_alerts_empty_response_returns_empty_list():
    client = WazuhAPIClient(CFG)
    empty_page = {"data": {"affected_items": []}}
    with patch("requests.post", return_value=_mock_response(200, {"data": {"token": "t"}})), \
         patch("requests.get", return_value=_mock_response(200, empty_page)):
        alerts = client.get_alerts()
    assert alerts == []


def test_get_alerts_unexpected_shape_stops_gracefully():
    client = WazuhAPIClient(CFG)
    weird_page = {"data": "not-a-list-or-dict-with-items"}
    with patch("requests.post", return_value=_mock_response(200, {"data": {"token": "t"}})), \
         patch("requests.get", return_value=_mock_response(200, weird_page)):
        alerts = client.get_alerts()
    assert alerts == []


# --- Fingerprint / conversion -------------------------------------------------------
def test_event_fingerprint_uses_wazuh_id_when_present():
    fp = event_fingerprint({"id": "abc123"})
    assert fp == "wazuh:abc123"


def test_event_fingerprint_deterministic_without_id():
    alert = {"timestamp": "2026-01-01T00:00:00Z", "rule": {"id": "5710"}, "agent": {"id": "001"}}
    assert event_fingerprint(alert) == event_fingerprint(alert)


def test_event_fingerprint_differs_for_different_alerts():
    a1 = {"timestamp": "2026-01-01T00:00:00Z", "rule": {"id": "5710"}}
    a2 = {"timestamp": "2026-01-01T00:01:00Z", "rule": {"id": "5711"}}
    assert event_fingerprint(a1) != event_fingerprint(a2)


def test_wazuh_alert_to_raw_event_maps_windows_fields():
    alert = {
        "timestamp": "2026-01-01T09:00:00Z",
        "agent": {"name": "WKS-01", "id": "001"},
        "rule": {"id": "60122", "description": "Multiple failed logins", "level": 10},
        "data": {
            "win": {
                "system": {"eventID": "4625"},
                "eventdata": {"targetUserName": "bob", "ipAddress": "198.51.100.66"},
            }
        },
    }
    raw = wazuh_alert_to_raw_event(alert)
    assert raw["user"] == "bob"
    assert raw["source_ip"] == "198.51.100.66"
    assert raw["hostname"] == "WKS-01"
    assert raw["event_code"] == "4625"
    assert raw["status"] == "failure"


def test_wazuh_alert_to_raw_event_handles_missing_fields_safely():
    raw = wazuh_alert_to_raw_event({"timestamp": "2026-01-01T00:00:00Z"})
    assert raw["user"] is None
    assert raw["source_ip"] is None


# --- Duplicate prevention ------------------------------------------------------------
def test_duplicate_fingerprint_detection():
    repository.mark_wazuh_fingerprints_seen(["wazuh:abc123"])
    assert repository.is_wazuh_fingerprint_seen("wazuh:abc123") is True
    assert repository.is_wazuh_fingerprint_seen("wazuh:not-seen") is False


# --- Full sync orchestration ---------------------------------------------------------
def test_sync_wazuh_events_not_configured_returns_clear_error():
    with patch("integrations.wazuh_api_client.WazuhAPIClient") as mock_client_cls:
        mock_client_cls.return_value.is_configured = False
        result = sync_wazuh_events()
    assert result["success"] is False
    assert "not configured" in result["error"].lower()


def test_sync_wazuh_events_never_raises_on_api_failure():
    with patch("integrations.wazuh_api_client.WazuhAPIClient") as mock_client_cls:
        instance = mock_client_cls.return_value
        instance.is_configured = True
        instance.get_alerts.side_effect = WazuhAPIError("connection refused")
        result = sync_wazuh_events()  # must not raise
    assert result["success"] is False
    assert "connection refused" in result["error"]


def test_sync_wazuh_events_ingests_new_events_end_to_end():
    fake_alert = {
        "id": "unique-alert-1",
        "timestamp": "2026-01-01T09:00:00Z",
        "agent": {"name": "WKS-TEST"},
        "rule": {"id": "5710"},
        "data": {"win": {"system": {"eventID": "4624"}, "eventdata": {"targetUserName": "alice"}}},
    }
    with patch("integrations.wazuh_api_client.WazuhAPIClient") as mock_client_cls:
        instance = mock_client_cls.return_value
        instance.is_configured = True
        instance.get_alerts.return_value = [fake_alert]
        result = sync_wazuh_events(max_events=10)

    assert result["success"] is True
    assert result["events_retrieved"] == 1
    assert result["events_ingested"] == 1


def test_sync_wazuh_events_skips_already_ingested_duplicates():
    fake_alert = {"id": "dup-alert-1", "timestamp": "2026-01-01T09:00:00Z", "data": {}}
    repository.mark_wazuh_fingerprints_seen([event_fingerprint(fake_alert)])

    with patch("integrations.wazuh_api_client.WazuhAPIClient") as mock_client_cls:
        instance = mock_client_cls.return_value
        instance.is_configured = True
        instance.get_alerts.return_value = [fake_alert]
        result = sync_wazuh_events()

    assert result["success"] is True
    assert result["events_retrieved"] == 1
    assert result["events_ingested"] == 0  # already-seen fingerprint was skipped
