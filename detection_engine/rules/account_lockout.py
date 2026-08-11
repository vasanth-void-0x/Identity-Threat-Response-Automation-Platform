"""
detection_engine/rules/account_lockout.py
7.8 Account Lockout - detects Event ID 4740 and correlates it with prior
failed login activity for the same user.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent


class AccountLockoutRule(BaseDetectionRule):
    rule_name = "account_lockout"
    mitre_techniques = ["T1110"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        window_minutes = self.config.get("correlation_window_minutes", 15)
        lockouts = [e for e in events if e.event_type == "account_locked_out"]
        failures = [e for e in events if e.event_type == "logon_failure"]

        alerts: list[Alert] = []
        for lockout in lockouts:
            related_failures = [
                f for f in failures
                if f.user == lockout.user
                and timedelta(0) <= (lockout.timestamp - f.timestamp) <= timedelta(minutes=window_minutes)
            ]
            alerts.append(self._make_alert(
                title=f"Account lockout for '{lockout.user}'",
                description=(
                    f"Account '{lockout.user}' was locked out on '{lockout.hostname}', "
                    f"correlated with {len(related_failures)} prior failed logon attempt(s)."
                ),
                event_ids=[lockout.event_id] + [f.event_id for f in related_failures],
                user=lockout.user,
                source_ip=lockout.source_ip,
                hostname=lockout.hostname,
                metadata={"related_failure_count": len(related_failures)},
                created_at=lockout.timestamp,
            ))
        return alerts
