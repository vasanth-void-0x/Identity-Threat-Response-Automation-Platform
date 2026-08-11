"""
tests/test_baseline.py
Tests for the known-IP / known-device baseline fix: seeding from
sample_data/users.json into the known_ips table, and the detection engine
loading/persisting that baseline correctly.
"""

from database import repository
from database.seed import seed_users_and_devices
from detection_engine.engine import DetectionEngine
from detection_engine.rules.new_device import NewDeviceRule
from detection_engine.rules.new_source_ip import NewSourceIPRule
from parsers.normalizer import normalize_raw_event
from tests.conftest import make_raw_event


def test_seed_users_and_devices_populates_known_ips_table(tmp_path, monkeypatch):
    # Point SAMPLE_DATA_DIR at a tiny fixture users.json for an isolated test
    import json
    import database.seed as seed_module

    fixture_dir = tmp_path / "sample_data"
    fixture_dir.mkdir()
    (fixture_dir / "users.json").write_text(json.dumps([
        {"username": "testuser", "known_ips": ["192.0.2.99"], "known_devices": ["WKS-TEST"]}
    ]))

    monkeypatch.setattr(seed_module, "SAMPLE_DATA_DIR", fixture_dir)
    seed_users_and_devices()

    known_ips = repository.load_known_ips()
    assert "testuser" in known_ips
    assert "192.0.2.99" in known_ips["testuser"]


def test_known_ip_does_not_trigger_new_source_ip_alert():
    """A user logging in from their persisted baseline IP should not alert."""
    repository.save_known_ips({"alice": {"192.0.2.10"}})

    events = [normalize_raw_event(make_raw_event(user="alice", source_ip="192.0.2.10"))]
    engine = DetectionEngine()
    alerts, _ = engine.run(events)

    new_ip_alerts = [a for a in alerts if a.rule_name == "new_source_ip"]
    assert new_ip_alerts == []


def test_unknown_ip_triggers_new_source_ip_alert_against_persisted_baseline():
    """A login from an IP NOT in the persisted baseline should alert, using DB-loaded context."""
    repository.save_known_ips({"alice": {"192.0.2.10"}})

    events = [normalize_raw_event(make_raw_event(user="alice", source_ip="198.51.100.66"))]
    engine = DetectionEngine()
    alerts, _ = engine.run(events)

    new_ip_alerts = [a for a in alerts if a.rule_name == "new_source_ip"]
    assert len(new_ip_alerts) == 1
    assert new_ip_alerts[0].source_ip == "198.51.100.66"


def test_first_time_user_does_not_alert_on_first_sighting():
    """A brand-new user with no baseline at all should not generate a false new-IP alert
    on their very first login (baseline is established, not immediately flagged)."""
    events = [normalize_raw_event(make_raw_event(user="brand_new_user", source_ip="192.0.2.77"))]
    rule = NewSourceIPRule()
    alerts = rule.evaluate(events, {"known_ips": repository.load_known_ips()})
    assert alerts == []


def test_new_ip_is_not_automatically_persisted_after_detection_run():
    """Detection must not silently trust an observed address."""
    repository.save_known_ips({"bob": {"192.0.2.20"}})

    events = [normalize_raw_event(make_raw_event(user="bob", source_ip="203.0.113.50"))]
    engine = DetectionEngine()
    engine.run(events)

    updated_baseline = repository.load_known_ips()
    assert "203.0.113.50" not in updated_baseline["bob"]


def test_analyst_can_explicitly_trust_and_remove_ip():
    repository.add_trusted_ip("bob", "203.0.113.50", "analyst1", "Verified corporate VPN")
    assert "203.0.113.50" in repository.load_known_ips()["bob"]
    repository.remove_trusted_ip("bob", "203.0.113.50", "analyst1")
    assert "203.0.113.50" not in repository.load_known_ips().get("bob", set())


def test_duplicate_unknown_ip_alert_is_suppressed_within_batch():
    repository.save_known_ips({"alice": {"192.0.2.10"}})
    events = [normalize_raw_event(make_raw_event(user="alice", source_ip="198.51.100.66")) for _ in range(2)]
    alerts = NewSourceIPRule().evaluate(events, {"known_ips": repository.load_known_ips()})
    assert len(alerts) == 1


def test_known_device_does_not_trigger_new_device_alert():
    repository.save_known_devices({"charlie": {"WKS-CHARLIE-01"}})

    events = [normalize_raw_event(make_raw_event(user="charlie", device="WKS-CHARLIE-01"))]
    rule = NewDeviceRule()
    alerts = rule.evaluate(events, {"known_devices": repository.load_known_devices()})
    assert alerts == []


def test_unknown_device_triggers_new_device_alert():
    repository.save_known_devices({"charlie": {"WKS-CHARLIE-01"}})

    events = [normalize_raw_event(make_raw_event(user="charlie", device="SRV-UNKNOWN-99"))]
    rule = NewDeviceRule()
    alerts = rule.evaluate(events, {"known_devices": repository.load_known_devices()})
    assert len(alerts) == 1
    assert alerts[0].device_id == "SRV-UNKNOWN-99"


def test_engine_loads_baseline_from_database_automatically():
    """DetectionEngine.run() should load known_ips/known_devices from the DB without
    the caller having to pass them manually."""
    repository.save_known_ips({"testadmin": {"192.0.2.50"}})
    repository.save_known_devices({"testadmin": {"SRV-DC-01"}})

    events = [normalize_raw_event(make_raw_event(
        user="testadmin", source_ip="192.0.2.50", device="SRV-DC-01",
    ))]
    engine = DetectionEngine()
    alerts, _ = engine.run(events)

    assert not any(a.rule_name in ("new_source_ip", "new_device") for a in alerts)
