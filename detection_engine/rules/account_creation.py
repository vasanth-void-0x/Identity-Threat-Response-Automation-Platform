"""
detection_engine/rules/account_creation.py
7.9 Account Creation - detects Event ID 4720, raising severity when created
outside business hours or when quickly followed by a privileged group add.
MITRE T1136.001 - Create Account: Local Account.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from core.validators import is_business_hours
from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent


class AccountCreationRule(BaseDetectionRule):
    rule_name = "account_creation"
    mitre_techniques = ["T1136.001"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        window_minutes = self.config.get("correlation_window_minutes", 30)
        creations = [e for e in events if e.event_type == "account_created"]
        group_adds = [
            e for e in events
            if e.event_type in ("global_group_member_added", "local_group_member_added")
        ]

        alerts: list[Alert] = []
        for c in creations:
            risk_factors = []
            if not is_business_hours(c.timestamp):
                risk_factors.append("created outside business hours")

            follow_up_adds = [
                g for g in group_adds
                if g.target_user == c.target_user
                and timedelta(0) <= (g.timestamp - c.timestamp) <= timedelta(minutes=window_minutes)
            ]
            if follow_up_adds:
                risk_factors.append("quickly added to a security group after creation")

            alerts.append(self._make_alert(
                title=f"New user account created: '{c.target_user or c.user}'",
                description=(
                    f"Account '{c.target_user or c.user}' was created by '{c.user}' on '{c.hostname}'."
                    + (f" Risk factors: {', '.join(risk_factors)}." if risk_factors else "")
                ),
                event_ids=[c.event_id] + [g.event_id for g in follow_up_adds],
                user=c.user,
                source_ip=c.source_ip,
                hostname=c.hostname,
                metadata={"target_user": c.target_user, "risk_factors": risk_factors},
                created_at=c.timestamp,
            ))
        return alerts
