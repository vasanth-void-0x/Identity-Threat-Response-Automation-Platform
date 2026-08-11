"""Splunk connector tests; all HTTP and system-changing operations are mocked."""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from core.config import SplunkAPIConfig
from integrations.splunk_api_client import (
    SplunkAPIClient, SplunkAPIError, event_fingerprint, splunk_result_to_raw_event,
)

CFG = SplunkAPIConfig(url="https://localhost:8089", token="fake.jwt.token", index="main",
                      sourcetype="WinEventLog:Security", verify_ssl=False)


def response(status=200, payload=None, text=None):
    r = MagicMock(status_code=status)
    r.json.return_value = payload or {}
    r.text = text if text is not None else json.dumps(payload or {})
    return r


def test_connection_success():
    payload = {"entry": [{"name": "server-info", "content": {"version": "10.4.1"}}]}
    with patch("requests.request", return_value=response(payload=payload)):
        result = SplunkAPIClient(CFG).test_connection()
    assert result == {"connected": True, "version": "10.4.1", "server_name": "server-info"}


def test_connection_auth_failure_hides_token():
    with patch("requests.request", return_value=response(status=401)):
        result = SplunkAPIClient(CFG).test_connection()
    assert result["connected"] is False
    assert CFG.token not in result["error"]


def test_timeout_is_actionable():
    with patch("requests.request", side_effect=requests.exceptions.Timeout()):
        with pytest.raises(SplunkAPIError, match="timed out"):
            SplunkAPIClient(CFG).export_events()


def test_export_parses_newline_json_and_bounds_results():
    lines = "\n".join(json.dumps({"result": {"_time": f"2026-08-07T10:00:0{i}Z", "EventCode": "4672"}}) for i in range(2))
    with patch("requests.request", return_value=response(text=lines)) as request:
        records = SplunkAPIClient(CFG).export_events(max_events=2)
    assert len(records) == 2
    sent_search = request.call_args.kwargs["data"]["search"]
    assert 'index="main"' in sent_search
    assert "head 2" in sent_search


def test_result_conversion_matches_normalizer_shape():
    raw = splunk_result_to_raw_event({
        "_time": "2026-08-07T10:00:00Z", "EventCode": "4624",
        "TargetUserName": "alice", "IpAddress": "203.0.113.10", "host": "SASUKE",
    })
    assert raw["event_code"] == "4624"
    assert raw["user"] == "alice"
    assert raw["hostname"] == "SASUKE"


def test_result_conversion_extracts_user_from_unparsed_windows_raw_event():
    raw = splunk_result_to_raw_event({
        "_time": "2026-08-07 15:51:45.329 India Standard Time",
        "EventCode": "4672",
        "host": "SASUKE",
        "_raw": "Special privileges assigned to new logon:\n  Account Name: VASANTH\n",
    })
    assert raw["user"] == "VASANTH"


def test_fingerprint_is_deterministic_and_distinct():
    one = {"_time": "2026-08-07T10:00:00Z", "EventCode": "4624", "RecordNumber": "1"}
    two = dict(one, RecordNumber="2")
    assert event_fingerprint(one) == event_fingerprint(one)
    assert event_fingerprint(one) != event_fingerprint(two)


def test_unsafe_index_is_rejected_before_network():
    bad = CFG.model_copy(update={"index": 'main | delete'})
    with patch("requests.request") as request:
        with pytest.raises(SplunkAPIError, match="Unsafe"):
            SplunkAPIClient(bad).export_events()
    request.assert_not_called()
