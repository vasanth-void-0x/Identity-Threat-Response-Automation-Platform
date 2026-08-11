"""
detection_engine/rules/successful_login_after_failures.py
7.2 Successful Login After Multiple Failures - detects a 4624 success shortly
after several 4625 failures for the same user. MITRE T1078 + T1110.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent


class SuccessfulLoginAfterFailuresRule(BaseDetectionRule):
    rule_name = "successful_login_after_failures"
    mitre_techniques = ["T1078", "T1110"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        min_failures = self.config.get("min_prior_failures", 3)
        window_minutes = self.config.get("window_minutes", 10)

        by_user: dict[str, list[NormalizedEvent]] = {}
        for e in events:
            if e.user and e.event_type in ("logon_failure", "logon_success"):
                by_user.setdefault(e.user, []).append(e)

        alerts: list[Alert] = []
        for user, evs in by_user.items():
            evs.sort(key=lambda x: x.timestamp)
            recent_failures: list[NormalizedEvent] = []
            for e in evs:
                if e.event_type == "logon_failure":
                    recent_failures.append(e)
                    recent_failures = [
                        f for f in recent_failures
                        if (e.timestamp - f.timestamp) <= timedelta(minutes=window_minutes)
                    ]
                elif e.event_type == "logon_success" and len(recent_failures) >= min_failures:
                    alerts.append(self._make_alert(
                        title=f"Successful login after {len(recent_failures)} failed attempts: '{user}'",
                        description=(
                            f"User '{user}' successfully authenticated after "
                            f"{len(recent_failures)} failed attempts within {window_minutes} minutes - "
                            "possible successful brute force or credential stuffing."
                        ),
                        event_ids=[f.event_id for f in recent_failures] + [e.event_id],
                        user=user,
                        source_ip=e.source_ip,
                        hostname=e.hostname,
                        metadata={"prior_failure_count": len(recent_failures)},
                        created_at=e.timestamp,
                    ))
                    recent_failures = []
        return alerts
