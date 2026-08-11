"""
detection_engine/risk_scoring.py
Explainable, configurable risk scoring for alerts and incidents.
Weights are loaded from configs/risk_weights.yaml so they can be tuned
without touching code. Every score is broken down into human-readable
contributions.
"""

from __future__ import annotations

from core.config import get_risk_weights
from core.constants import score_to_severity
from models.alert import Alert, RiskContribution

DEFAULT_WEIGHTS = {
    "brute_force": 20,
    "successful_login_after_failures": 25,
    "new_source_ip": 15,
    "new_device": 15,
    "impossible_travel": 35,
    "privileged_logon": 20,
    "suspicious_powershell": 30,
    "account_lockout": 15,
    "account_creation": 15,
    "account_creation_outside_hours": 20,
    "group_membership_change": 20,
    "group_membership_change_privileged": 35,
    "suspicious_process": 25,
    "known_malicious_ip": 30,
}


def _rule_base_score(alert: Alert, weights: dict) -> tuple[int, str]:
    rule = alert.rule_name
    if rule == "account_creation" and "created outside business hours" in " ".join(
        alert.metadata.get("risk_factors", [])
    ):
        return weights.get("account_creation_outside_hours", DEFAULT_WEIGHTS["account_creation_outside_hours"]), \
            "Account created outside business hours"
    if rule == "group_membership_change" and alert.metadata.get("is_privileged_group"):
        return weights.get("group_membership_change_privileged",
                            DEFAULT_WEIGHTS["group_membership_change_privileged"]), \
            "Added to a privileged security group"
    weight = weights.get(rule, DEFAULT_WEIGHTS.get(rule, 10))
    return weight, f"Rule '{rule}' triggered"


def score_alert(alert: Alert, threat_intel_malicious: bool = False) -> Alert:
    """Computes and attaches an explainable risk score to a single alert."""
    weights = {**DEFAULT_WEIGHTS, **get_risk_weights().get("weights", {})}

    base_score, reason = _rule_base_score(alert, weights)
    contributions = [RiskContribution(reason=reason, points=base_score)]

    total = base_score

    if threat_intel_malicious:
        ti_points = weights.get("known_malicious_ip", DEFAULT_WEIGHTS["known_malicious_ip"])
        contributions.append(RiskContribution(reason="Source IP has known-malicious threat intel reputation",
                                                points=ti_points))
        total += ti_points

    total = min(100, total)

    alert.base_score = base_score
    alert.contributions = contributions
    alert.final_score = total
    alert.severity = score_to_severity(total)
    alert.explanation = "; ".join(f"{c.reason} (+{c.points})" for c in contributions)

    return alert


def score_incident(rule_scores: dict[str, int]) -> tuple[int, str]:
    """
    Computes an incident's overall risk score from the highest alert score
    contributed by each *distinct* detection rule in the correlated cluster
    (rule_scores: {rule_name: max_final_score_for_that_rule}).

    Rather than simply taking the single worst alert, this dampens and sums
    the unique-rule contributions - reflecting that a multi-stage attack
    chain (e.g. brute force -> new host login -> privileged logon ->
    suspicious PowerShell) is materially more dangerous than any one stage
    alone, per the platform's design goal of surfacing one CRITICAL incident
    for a full attack sequence rather than several disconnected medium alerts.
    The result is floored at the single highest contributing alert's score
    and capped at 100.
    """
    if not rule_scores:
        return 0, score_to_severity(0)

    total = sum(rule_scores.values())
    floor = max(rule_scores.values())

    scaled = int(total * 0.55 + 0.5)  # dampened sum, avoids runaway scores with many rules
    final = max(floor, min(100, scaled))

    return final, score_to_severity(final)
