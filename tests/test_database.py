"""tests/test_database.py - Tests for the SQLite repository layer (uses isolated temp DB)."""

from database import repository
from models.alert import Alert
from models.event import NormalizedEvent
from models.incident import Incident


def test_save_and_count_events():
    events = [NormalizedEvent(timestamp="2026-07-20T09:00:00Z", user="alice", event_type="logon_success")]
    saved = repository.save_events(events)
    assert saved == 1
    assert repository.get_event_count() == 1


def test_save_and_get_alerts():
    alert = Alert(rule_name="brute_force", title="Test alert", description="d", user="bob", severity="high")
    repository.save_alerts([alert])
    alerts = repository.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["user"] == "bob"


def test_alert_filtering():
    repository.save_alerts([
        Alert(rule_name="brute_force", title="a1", description="d", user="alice", severity="high"),
        Alert(rule_name="new_device", title="a2", description="d", user="bob", severity="low"),
    ])
    high_alerts = repository.get_alerts(severity="high")
    assert len(high_alerts) == 1
    assert high_alerts[0]["user"] == "alice"


def test_save_and_get_incident():
    incident = Incident(title="Test incident", severity="high", risk_score=75, user="charlie")
    repository.save_incidents([incident])
    fetched = repository.get_incident(incident.incident_id)
    assert fetched is not None
    assert fetched["title"] == "Test incident"
    assert fetched["risk_score"] == 75


def test_update_incident_status():
    incident = Incident(title="Test", severity="medium", risk_score=40)
    repository.save_incidents([incident])
    repository.update_incident_status(incident.incident_id, "contained", actor="analyst1")
    fetched = repository.get_incident(incident.incident_id)
    assert fetched["status"] == "contained"


def test_add_investigation_note():
    incident = Incident(title="Test", severity="medium", risk_score=40)
    repository.save_incidents([incident])
    repository.add_investigation_note(incident.incident_id, "Verified with user", author="analyst1")
    fetched = repository.get_incident(incident.incident_id)
    assert any("Verified with user" in n for n in fetched["investigation_notes"])


def test_mark_false_positive():
    incident = Incident(title="Test", severity="low", risk_score=20)
    repository.save_incidents([incident])
    repository.mark_false_positive(incident.incident_id, actor="analyst1")
    fetched = repository.get_incident(incident.incident_id)
    assert fetched["is_false_positive"] is True
    assert fetched["status"] == "false_positive"


def test_known_ips_roundtrip():
    repository.save_known_ips({"alice": {"192.0.2.10", "192.0.2.11"}})
    loaded = repository.load_known_ips()
    assert loaded["alice"] == {"192.0.2.10", "192.0.2.11"}


def test_audit_log():
    repository.log_audit(actor="analyst1", action="test_action", target="INC-1234", details={"key": "value"})
    logs = repository.get_audit_logs()
    assert len(logs) == 1
    assert logs[0]["actor"] == "analyst1"


def test_overview_stats_empty_db():
    stats = repository.get_overview_stats()
    assert stats["total_events"] == 0
    assert stats["mean_risk_score"] == 0
