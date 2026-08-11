"""
detection_engine/rules/new_source_ip.py
7.3 New Source IP - detects a successful login from an IP not previously seen
for that user. The first known event establishes the baseline (no alert fires
on the very first sighting of a brand-new user).
"""

from __future__ import annotations

from typing import Any

from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent


class NewSourceIPRule(BaseDetectionRule):
    rule_name = "new_source_ip"
    mitre_techniques = ["T1078"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        known_ips: dict[str, set[str]] = context.get("known_ips", {})
        session_ips: dict[str, set[str]] = {user: set(values) for user, values in known_ips.items()}
        batch_seen: set[tuple[str, str]] = set()
        alerts: list[Alert] = []

        successes = sorted(
            [e for e in events if e.event_type == "logon_success" and e.user and e.source_ip],
            key=lambda x: x.timestamp,
        )

        for e in successes:
            seen = session_ips.setdefault(e.user, set())
            key = (e.user, e.source_ip)
            if key in batch_seen:
                continue
            batch_seen.add(key)
            if seen and e.source_ip not in seen:
                alerts.append(self._make_alert(
                    title=f"Login from new source IP for '{e.user}'",
                    description=(
                        f"User '{e.user}' logged in from IP {e.source_ip}, which has not "
                        f"been previously associated with this account (known IPs: {len(seen)})."
                    ),
                    event_ids=[e.event_id],
                    user=e.user,
                    source_ip=e.source_ip,
                    hostname=e.hostname,
                    metadata={"known_ip_count": len(seen)},
                    created_at=e.timestamp,
                ))
            seen.add(e.source_ip)  # batch-local only; never persisted or written to context
        return alerts
