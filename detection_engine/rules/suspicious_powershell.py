"""
detection_engine/rules/suspicious_powershell.py
7.7 Suspicious PowerShell - detects known-suspicious PowerShell invocation
patterns in Event ID 4104 script block logs. Detection-only string matching;
no real payloads are executed or included. MITRE T1059.001.
"""

from __future__ import annotations

from typing import Any

from core.constants import SUSPICIOUS_POWERSHELL_INDICATORS
from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent


class SuspiciousPowerShellRule(BaseDetectionRule):
    rule_name = "suspicious_powershell"
    mitre_techniques = ["T1059.001"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        powershell_events = [
            e for e in events
            if e.event_type == "powershell_script_block" or (e.command_line and "powershell" in (e.process_name or "").lower())
        ]

        for e in powershell_events:
            indicators = e.metadata.get("suspicious_indicators")
            if indicators is None:
                cmd = (e.command_line or "").lower()
                indicators = [ind for ind in SUSPICIOUS_POWERSHELL_INDICATORS if ind in cmd]

            if indicators:
                alerts.append(self._make_alert(
                    title=f"Suspicious PowerShell execution by '{e.user or 'unknown'}'",
                    description=(
                        f"PowerShell activity on '{e.hostname}' matched suspicious indicator(s): "
                        f"{', '.join(indicators)}."
                    ),
                    event_ids=[e.event_id],
                    user=e.user,
                    source_ip=e.source_ip,
                    hostname=e.hostname,
                    metadata={"indicators": indicators, "command_line": e.command_line},
                    created_at=e.timestamp,
                ))
        return alerts
