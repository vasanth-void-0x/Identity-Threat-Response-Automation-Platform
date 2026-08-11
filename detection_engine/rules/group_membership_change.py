"""
detection_engine/rules/group_membership_change.py
7.10 Privileged Group Membership Change - detects Event IDs 4728/4732 into
sensitive groups (Administrators, Domain Admins, Enterprise Admins, etc.).
MITRE T1098 - Account Manipulation.
"""

from __future__ import annotations

from typing import Any

from core.constants import PRIVILEGED_GROUPS
from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent


class GroupMembershipChangeRule(BaseDetectionRule):
    rule_name = "group_membership_change"
    mitre_techniques = ["T1098", "T1069"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        group_adds = [
            e for e in events
            if e.event_type in ("global_group_member_added", "local_group_member_added")
        ]

        for e in group_adds:
            group_name = str(e.raw_event.get("group_name") or e.raw_event.get("GroupName") or "").lower()
            is_privileged = any(g in group_name for g in PRIVILEGED_GROUPS)

            alerts.append(self._make_alert(
                title=(
                    f"Privileged group membership change: '{e.target_user}' added to '{group_name}'"
                    if is_privileged else
                    f"Group membership change: '{e.target_user}' added to '{group_name}'"
                ),
                description=(
                    f"'{e.target_user}' was added to group '{group_name}' by '{e.user}' on '{e.hostname}'."
                    + (" This is a privileged/sensitive security group." if is_privileged else "")
                ),
                event_ids=[e.event_id],
                user=e.user,
                source_ip=e.source_ip,
                hostname=e.hostname,
                metadata={
                    "target_user": e.target_user,
                    "group_name": group_name,
                    "is_privileged_group": is_privileged,
                },
                created_at=e.timestamp,
            ))
        return alerts
