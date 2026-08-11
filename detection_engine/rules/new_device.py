"""
detection_engine/rules/new_device.py
7.4 New Device or Hostname - detects login from a device/hostname not
previously associated with the user. Baseline established on first sighting.
"""

from __future__ import annotations

from typing import Any

from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent


class NewDeviceRule(BaseDetectionRule):
    rule_name = "new_device"
    mitre_techniques = ["T1078"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        known_devices: dict[str, set[str]] = context.get("known_devices", {})
        session_devices: dict[str, set[str]] = {user: set(values) for user, values in known_devices.items()}
        batch_seen: set[tuple[str, str]] = set()
        alerts: list[Alert] = []

        successes = sorted(
            [e for e in events if e.event_type == "logon_success" and e.user and (e.device_id or e.hostname)],
            key=lambda x: x.timestamp,
        )

        for e in successes:
            device_key = e.device_id or e.hostname
            seen = session_devices.setdefault(e.user, set())
            key = (e.user, device_key)
            if key in batch_seen:
                continue
            batch_seen.add(key)
            if seen and device_key not in seen:
                alerts.append(self._make_alert(
                    title=f"Login from new device for '{e.user}'",
                    description=(
                        f"User '{e.user}' logged in from device/host '{device_key}', which has not "
                        f"been previously seen for this account (known devices: {len(seen)})."
                    ),
                    event_ids=[e.event_id],
                    user=e.user,
                    source_ip=e.source_ip,
                    hostname=e.hostname,
                    device_id=e.device_id,
                    metadata={"known_device_count": len(seen)},
                    created_at=e.timestamp,
                ))
            seen.add(device_key)  # batch-local only; never persisted or written to context
        return alerts
