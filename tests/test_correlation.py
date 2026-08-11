"""tests/test_correlation.py - Tests for the alert correlation engine."""

from detection_engine.correlation import correlate_alerts
from models.alert import Alert


def _alert(rule_name, user=None, source_ip=None, hostname=None, score=50):
    a = Alert(rule_name=rule_name, title=f"{rule_name} alert", description="test",
              user=user, source_ip=source_ip, hostname=hostname)
    a.final_score = score
    a.severity = "high" if score >= 60 else "medium"
    return a


def test_correlate_single_alert_produces_single_incident():
    alerts = [_alert("brute_force", user="bob")]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert incidents[0].related_alert_ids == [alerts[0].alert_id]


def test_correlate_groups_alerts_sharing_user():
    alerts = [
        _alert("brute_force", user="charlie", score=40),
        _alert("privileged_logon", user="charlie", score=60),
        _alert("suspicious_powershell", user="charlie", score=70),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    incident = incidents[0]
    assert len(incident.related_alert_ids) == 3
    assert incident.risk_score >= 70  # correlation bonus applied


def test_correlate_keeps_unrelated_alerts_separate():
    alerts = [
        _alert("brute_force", user="alice", source_ip="192.0.2.10"),
        _alert("brute_force", user="bob", source_ip="192.0.2.20"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2


def test_correlate_empty_list():
    assert correlate_alerts([]) == []
