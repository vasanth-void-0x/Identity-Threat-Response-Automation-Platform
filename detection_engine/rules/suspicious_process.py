"""
detection_engine/rules/suspicious_process.py
7.11 Suspicious Process Creation - detects unusual parent-child process
relationships from Event ID 4688 / Sysmon Event ID 1 (e.g. Office app
spawning PowerShell, browser spawning cmd.exe). Safe, pattern-based only.
"""

from __future__ import annotations

from typing import Any

from detection_engine.base_rule import BaseDetectionRule
from models.alert import Alert
from models.event import NormalizedEvent

SUSPICIOUS_PARENT_CHILD_PAIRS = [
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("chrome.exe", "cmd.exe"),
    ("msedge.exe", "cmd.exe"),
    ("powershell.exe", "wscript.exe"),
    ("powershell.exe", "cscript.exe"),
    ("cmd.exe", "powershell.exe"),
]


class SuspiciousProcessRule(BaseDetectionRule):
    rule_name = "suspicious_process"
    mitre_techniques = ["T1204", "T1059.001"]

    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        process_events = [
            e for e in events
            if e.event_type in ("process_created", "sysmon_process_creation") and e.process_name
        ]

        for e in process_events:
            child = (e.process_name or "").lower().split("\\")[-1]
            parent = (e.parent_process or "").lower().split("\\")[-1]
            if not parent:
                continue

            if (parent, child) in SUSPICIOUS_PARENT_CHILD_PAIRS:
                alerts.append(self._make_alert(
                    title=f"Suspicious process relationship: {parent} -> {child}",
                    description=(
                        f"Process '{child}' (PID {e.process_id}) was spawned by '{parent}' "
                        f"on '{e.hostname}' - an unusual parent-child relationship associated "
                        "with user-execution based initial access techniques."
                    ),
                    event_ids=[e.event_id],
                    user=e.user,
                    source_ip=e.source_ip,
                    hostname=e.hostname,
                    metadata={"parent_process": parent, "child_process": child, "command_line": e.command_line},
                    created_at=e.timestamp,
                ))
        return alerts
