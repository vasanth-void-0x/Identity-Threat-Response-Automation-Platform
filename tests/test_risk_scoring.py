"""tests/test_risk_scoring.py - Tests for the explainable risk scoring engine."""

from core.constants import score_to_severity
from detection_engine.risk_scoring import score_alert, score_incident
from models.alert import Alert


def test_score_to_severity_bands():
    assert score_to_severity(10) == "low"
    assert score_to_severity(45) == "medium"
    assert score_to_severity(70) == "high"
    assert score_to_severity(95) == "critical"


def test_score_alert_basic():
    alert = Alert(rule_name="brute_force", title="t", description="d")
    scored = score_alert(alert)
    assert scored.final_score > 0
    assert scored.severity in ("low", "medium", "high", "critical")
    assert len(scored.contributions) >= 1
    assert scored.explanation


def test_score_alert_with_threat_intel_bonus():
    alert1 = Alert(rule_name="new_source_ip", title="t", description="d")
    alert2 = Alert(rule_name="new_source_ip", title="t", description="d")
    scored1 = score_alert(alert1, threat_intel_malicious=False)
    scored2 = score_alert(alert2, threat_intel_malicious=True)
    assert scored2.final_score > scored1.final_score


def test_score_alert_caps_at_100():
    alert = Alert(rule_name="impossible_travel", title="t", description="d")
    scored = score_alert(alert, threat_intel_malicious=True)
    assert scored.final_score <= 100


def test_score_incident_multi_stage_scales_above_max_alert():
    rule_scores = {"brute_force": 20, "successful_login_after_failures": 25, "new_source_ip": 15,
                    "new_device": 15, "privileged_logon": 20, "suspicious_powershell": 30,
                    "suspicious_process": 25}
    score, severity = score_incident(rule_scores)
    assert score > max(rule_scores.values())  # multi-stage chain scores above any single alert
    assert severity == "critical"


def test_score_incident_never_below_highest_single_alert():
    rule_scores = {"brute_force": 20, "new_device": 15}
    score, severity = score_incident(rule_scores)
    assert score >= max(rule_scores.values())


def test_score_incident_caps_at_100():
    rule_scores = {f"rule_{i}": 35 for i in range(10)}
    score, severity = score_incident(rule_scores)
    assert score == 100
    assert severity == "critical"


def test_score_incident_empty():
    score, severity = score_incident({})
    assert score == 0
    assert severity == "low"
