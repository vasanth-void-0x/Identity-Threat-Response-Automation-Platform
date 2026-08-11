"""detection_engine/base_rule.py - Abstract base class every detection rule implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from models.alert import Alert
from models.event import NormalizedEvent


class BaseDetectionRule(ABC):
    """
    Every detection rule receives the full (time-ordered) list of normalized
    events for the current batch/session plus a shared context dict (for
    baselines like known IPs/devices), and returns zero or more Alerts.
    """

    rule_name: str = "base_rule"
    mitre_techniques: list[str] = []

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def evaluate(self, events: list[NormalizedEvent], context: dict[str, Any]) -> list[Alert]:
        """Returns a list of Alert objects for any suspicious activity found."""
        raise NotImplementedError

    def _make_alert(
        self,
        title: str,
        description: str,
        event_ids: list[str],
        user: str | None = None,
        source_ip: str | None = None,
        hostname: str | None = None,
        device_id: str | None = None,
        metadata: dict | None = None,
        created_at: datetime | None = None,
    ) -> Alert:
        """
        created_at should be the timestamp of the triggering/most-recent event
        in this alert's evidence, so alert and incident timelines reflect when
        the activity actually happened rather than when the batch was
        processed. Falls back to "now" only if no event timestamp is available.
        """
        kwargs = dict(
            rule_name=self.rule_name,
            title=title,
            description=description,
            event_ids=event_ids,
            user=user,
            source_ip=source_ip,
            hostname=hostname,
            device_id=device_id,
            mitre_techniques=list(self.mitre_techniques),
            metadata=metadata or {},
        )
        if created_at is not None:
            kwargs["created_at"] = created_at
        return Alert(**kwargs)
