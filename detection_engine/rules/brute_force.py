"""
detection_engine/rules/brute_force.py
7.1 Multiple Failed Logins - detects >= threshold Event ID 4625 failures for the
same user or source IP within a rolling time window. MITRE T1110 - Brute Force.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent


class BruteForceRule(BaseDetectionRule):
    rule_name = "brute_force"
    mitre_techniques = ["T1110"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        threshold = self.config.get("failure_threshold", 5)
        window_minutes = self.config.get("window_minutes", 5)

        failures = [e for e in events if e.event_type == "logon_failure"]
        buckets: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in failures:
            key = e.user or e.source_ip or "unknown"
            buckets[key].append(e)

        alerts: list[Alert] = []
        for key, evs in buckets.items():
            evs.sort(key=lambda x: x.timestamp)
            window: list[NormalizedEvent] = []
            for e in evs:
                window.append(e)
                window = [w for w in window if (e.timestamp - w.timestamp) <= timedelta(minutes=window_minutes)]
                if len(window) >= threshold:
                    alerts.append(self._make_alert(
                        title=f"Brute force login attempts detected for '{key}'",
                        description=(
                            f"{len(window)} failed login attempts for '{key}' "
                            f"within {window_minutes} minutes (threshold: {threshold})."
                        ),
                        event_ids=[w.event_id for w in window],
                        user=window[0].user,
                        source_ip=window[0].source_ip,
                        hostname=window[0].hostname,
                        metadata={"failure_count": len(window), "window_minutes": window_minutes},
                        created_at=window[-1].timestamp,
                    ))
                    window = []  # reset after firing to avoid duplicate overlapping alerts
        return alerts
