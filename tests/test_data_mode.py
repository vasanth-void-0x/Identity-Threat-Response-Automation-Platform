"""Regression coverage for source-aware dashboard modes."""

from unittest.mock import patch

from app.utils.data_mode import filter_alerts, filter_incidents


def test_live_and_demo_alerts_remain_separate():
    alerts = [{"alert_id": "live", "event_ids": ["e1"]}, {"alert_id": "demo", "event_ids": ["e2"]}]
    with patch("app.utils.data_mode.repository.get_event_sources", side_effect=[{"splunk_api"}, {"sample_data"}]):
        assert [a["alert_id"] for a in filter_alerts(alerts, "Live Splunk")] == ["live"]


def test_incident_mode_follows_related_alert_evidence():
    alerts = [{"alert_id": "a-live", "event_ids": ["e1"]}, {"alert_id": "a-demo", "event_ids": ["e2"]}]
    incidents = [
        {"incident_id": "i-live", "related_alert_ids": ["a-live"]},
        {"incident_id": "i-demo", "related_alert_ids": ["a-demo"]},
    ]
    with patch("app.utils.data_mode.repository.get_event_sources", side_effect=[{"splunk_api"}, {"sample_data"}]):
        selected = filter_incidents(incidents, alerts, "Live Splunk")
    assert [item["incident_id"] for item in selected] == ["i-live"]
