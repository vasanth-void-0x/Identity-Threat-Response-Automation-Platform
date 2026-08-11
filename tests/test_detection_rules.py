"""tests/test_detection_rules.py - Unit tests for each detection rule."""

from detection_engine.rules.account_creation import AccountCreationRule
from detection_engine.rules.account_lockout import AccountLockoutRule
from detection_engine.rules.brute_force import BruteForceRule
from detection_engine.rules.group_membership_change import GroupMembershipChangeRule
from detection_engine.rules.impossible_travel import ImpossibleTravelRule, haversine_distance_km
from detection_engine.rules.new_device import NewDeviceRule
from detection_engine.rules.new_source_ip import NewSourceIPRule
from detection_engine.rules.privileged_logon import PrivilegedLogonRule
from detection_engine.rules.successful_login_after_failures import SuccessfulLoginAfterFailuresRule
from detection_engine.rules.suspicious_powershell import SuspiciousPowerShellRule
from detection_engine.rules.suspicious_process import SuspiciousProcessRule
from parsers.normalizer import normalize_raw_event
from tests.conftest import make_raw_event


def _events(raws):
    return [normalize_raw_event(r) for r in raws]


def test_brute_force_rule_fires_on_threshold():
    raws = [
        make_raw_event(event_code="4625", status="failure",
                        timestamp=f"2026-07-20T09:00:{i:02d}Z", user="bob")
        for i in range(6)
    ]
    events = _events(raws)
    rule = BruteForceRule(config={"failure_threshold": 5, "window_minutes": 5})
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1
    assert alerts[0].rule_name == "brute_force"


def test_brute_force_rule_no_alert_below_threshold():
    raws = [
        make_raw_event(event_code="4625", status="failure",
                        timestamp=f"2026-07-20T09:00:{i:02d}Z", user="bob")
        for i in range(3)
    ]
    events = _events(raws)
    rule = BruteForceRule(config={"failure_threshold": 5, "window_minutes": 5})
    assert rule.evaluate(events, {}) == []


def test_successful_login_after_failures():
    raws = [make_raw_event(event_code="4625", status="failure",
                            timestamp=f"2026-07-20T09:00:{i:02d}Z", user="bob") for i in range(4)]
    raws.append(make_raw_event(event_code="4624", status="success",
                                timestamp="2026-07-20T09:05:00Z", user="bob"))
    events = _events(raws)
    rule = SuccessfulLoginAfterFailuresRule(config={"min_prior_failures": 3, "window_minutes": 10})
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1


def test_new_source_ip_rule_baseline_then_alert():
    events = _events([
        make_raw_event(source_ip="192.0.2.10", timestamp="2026-07-20T09:00:00Z"),
        make_raw_event(source_ip="198.51.100.66", timestamp="2026-07-20T10:00:00Z"),
    ])
    rule = NewSourceIPRule()
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1
    assert alerts[0].source_ip == "198.51.100.66"


def test_new_device_rule():
    events = _events([
        make_raw_event(device="WKS-1", timestamp="2026-07-20T09:00:00Z"),
        make_raw_event(device="WKS-2", timestamp="2026-07-20T10:00:00Z"),
    ])
    rule = NewDeviceRule()
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1


def test_impossible_travel_haversine():
    dist = haversine_distance_km(13.0827, 80.2707, 6.5244, 3.3792)  # Chennai -> Lagos
    assert 8000 < dist < 9000


def test_impossible_travel_rule_fires():
    events = _events([
        {**make_raw_event(timestamp="2026-07-20T09:00:00Z"),
         "location": {"city": "Chennai", "country": "IN", "lat": 13.0827, "lon": 80.2707}},
        {**make_raw_event(timestamp="2026-07-20T09:15:00Z"),
         "location": {"city": "Lagos", "country": "NG", "lat": 6.5244, "lon": 3.3792}},
    ])
    rule = ImpossibleTravelRule()
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1
    assert alerts[0].metadata["required_speed_kmh"] > 900


def test_privileged_logon_rule():
    events = _events([make_raw_event(event_code="4672", status="success")])
    rule = PrivilegedLogonRule()
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1


def test_suspicious_powershell_rule_detects_indicator():
    events = _events([make_raw_event(event_code="4104", command_line="powershell -enc AAAA", status="success")])
    rule = SuspiciousPowerShellRule()
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1
    assert "-enc " in alerts[0].metadata["indicators"]


def test_suspicious_powershell_rule_ignores_benign():
    events = _events([make_raw_event(event_code="4104", command_line="Get-Service", status="success")])
    rule = SuspiciousPowerShellRule()
    assert rule.evaluate(events, {}) == []


def test_account_lockout_rule():
    events = _events([make_raw_event(event_code="4740", status="success")])
    rule = AccountLockoutRule()
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1


def test_account_creation_rule_outside_business_hours():
    events = _events([make_raw_event(event_code="4720", target_user="svc_temp",
                                      timestamp="2026-07-19T02:00:00Z")])  # Sunday 2AM
    rule = AccountCreationRule()
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1
    assert "created outside business hours" in alerts[0].metadata["risk_factors"]


def test_group_membership_change_privileged():
    events = _events([make_raw_event(event_code="4732", target_user="svc_temp",
                                      group_name="Administrators")])
    rule = GroupMembershipChangeRule()
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1
    assert alerts[0].metadata["is_privileged_group"] is True


def test_suspicious_process_rule():
    events = _events([make_raw_event(
        event_code="4688", process_name="powershell.exe", parent_process="winword.exe",
        process_id="1234",
    )])
    rule = SuspiciousProcessRule()
    alerts = rule.evaluate(events, {})
    assert len(alerts) == 1
