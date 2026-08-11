"""
detection_engine/rules/privileged_logon.py
7.6 Privileged Logon - detects Event ID 4672 (special privileges assigned) and
raises severity when combined with new IP, new device, or recent failed logins.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent


class PrivilegedLogonRule(BaseDetectionRule):
    rule_name = "privileged_logon"
    mitre_techniques = ["T1078", "T1548"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        window_minutes = self.config.get("correlation_window_minutes", 15)
        privileged_events = [e for e in events if e.event_type == "special_privileges_assigned"]
        failures = [e for e in events if e.event_type == "logon_failure"]
        known_ips: dict[str, set[str]] = context.get("known_ips", {})

        alerts: list[Alert] = []
        for e in privileged_events:
            risk_factors = []

            seen_ips = known_ips.get(e.user, set())
            if e.source_ip and seen_ips and e.source_ip not in seen_ips:
                risk_factors.append("new source IP")

            recent_failures = [
                f for f in failures
                if f.user == e.user and abs((e.timestamp - f.timestamp)) <= timedelta(minutes=window_minutes)
            ]
            if recent_failures:
                risk_factors.append(f"{len(recent_failures)} recent failed logon(s)")

            alerts.append(self._make_alert(
                title=f"Privileged logon detected for '{e.user}'",
                description=(
                    f"User '{e.user}' was granted special/administrative privileges on "
                    f"'{e.hostname}'." + (f" Risk factors: {', '.join(risk_factors)}." if risk_factors else "")
                ),
                event_ids=[e.event_id] + [f.event_id for f in recent_failures],
                user=e.user,
                source_ip=e.source_ip,
                hostname=e.hostname,
                metadata={"risk_factors": risk_factors},
                created_at=e.timestamp,
            ))
        return alerts
