"""
tests/test_correlation_timestamps.py
Tests that alert and incident timestamps are derived from the underlying
event occurrence times, not from processing/wall-clock time - fixing the
bug where seeded demo alerts all appeared to happen at nearly the same
instant.
"""

from datetime import datetime, timezone

from detection_engine.correlation import correlate_alerts
from detection_engine.rules.brute_force import BruteForceRule
from parsers.normalizer import normalize_raw_event
from tests.conftest import make_raw_event


def test_brute_force_alert_timestamp_matches_event_time_not_now():
    raws = [
        make_raw_event(event_code="4625", status="failure", user="bob",
                        timestamp=f"2020-01-01T09:00:{i:02d}Z")
        for i in range(6)
    ]
    events = [normalize_raw_event(r) for r in raws]
    rule = BruteForceRule(config={"failure_threshold": 5, "window_minutes": 5})
    alerts = rule.evaluate(events, {})

    assert len(alerts) == 1
    # The alert's created_at must reflect the (deliberately ancient) event
    # timestamps, not "now" (which would be in 2026).
    assert alerts[0].created_at.year == 2020
    assert alerts[0].created_at != datetime.now(timezone.utc)


def test_incident_created_at_uses_earliest_alert_timestamp():
    from models.alert import Alert

    a1 = Alert(rule_name="brute_force", title="a1", description="d", user="alice",
               created_at=datetime(2020, 1, 1, 9, 0, 0, tzinfo=timezone.utc))
    a1.final_score = 40
    a2 = Alert(rule_name="privileged_logon", title="a2", description="d", user="alice",
               created_at=datetime(2020, 1, 1, 9, 15, 0, tzinfo=timezone.utc))
    a2.final_score = 60

    incidents = correlate_alerts([a1, a2])
    assert len(incidents) == 1
    assert incidents[0].created_at == datetime(2020, 1, 1, 9, 0, 0, tzinfo=timezone.utc)


def test_incident_updated_at_uses_latest_alert_timestamp():
    from models.alert import Alert

    a1 = Alert(rule_name="brute_force", title="a1", description="d", user="alice",
               created_at=datetime(2020, 1, 1, 9, 0, 0, tzinfo=timezone.utc))
    a1.final_score = 40
    a2 = Alert(rule_name="privileged_logon", title="a2", description="d", user="alice",
               created_at=datetime(2020, 1, 1, 9, 20, 0, tzinfo=timezone.utc))
    a2.final_score = 60

    incidents = correlate_alerts([a1, a2])
    assert len(incidents) == 1  # within the default 30-minute correlation window
    assert incidents[0].updated_at == datetime(2020, 1, 1, 9, 20, 0, tzinfo=timezone.utc)


def test_incident_timeline_entries_use_alert_timestamps():
    from models.alert import Alert

    a1 = Alert(rule_name="brute_force", title="Brute force detected", description="d", user="alice",
               created_at=datetime(2020, 1, 1, 9, 0, 0, tzinfo=timezone.utc))
    a1.final_score = 40

    incidents = correlate_alerts([a1])
    entry = incidents[0].timeline[0]
    assert entry.timestamp == datetime(2020, 1, 1, 9, 0, 0, tzinfo=timezone.utc)


def test_multi_stage_scenario_produces_ordered_realistic_timeline():
    """Simulates the correlated_attack.json style scenario and confirms
    the resulting incident's timeline is chronologically ordered and spans
    realistic event times rather than clustering at 'now'."""
    from models.alert import Alert

    times = [
        datetime(2020, 6, 1, 8, 0, 0, tzinfo=timezone.utc),
        datetime(2020, 6, 1, 8, 5, 0, tzinfo=timezone.utc),
        datetime(2020, 6, 1, 8, 10, 0, tzinfo=timezone.utc),
    ]
    alerts = []
    for i, t in enumerate(times):
        a = Alert(rule_name=f"rule_{i}", title=f"stage {i}", description="d", user="charlie", created_at=t)
        a.final_score = 30
        alerts.append(a)

    incidents = correlate_alerts(alerts)
    incident = incidents[0]
    timeline_times = [e.timestamp for e in incident.timeline]
    assert timeline_times == sorted(timeline_times)
    assert incident.created_at == times[0]
    assert incident.updated_at == times[-1]
