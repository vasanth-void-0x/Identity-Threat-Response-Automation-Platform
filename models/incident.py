"""models/incident.py - Incident: a correlated group of related alerts."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class TimelineEntry(BaseModel):
    timestamp: datetime
    description: str
    source: str = "system"  # system | analyst | automation


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str
    description: str = ""

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    user: Optional[str] = None
    source_ips: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)

    related_alert_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    risk_score: int = 0
    severity: str = "low"
    status: str = "new"  # new | triaged | investigating | contained | resolved | false_positive

    investigation_notes: list[str] = Field(default_factory=list)
    response_action_ids: list[str] = Field(default_factory=list)

    analyst_decision: Optional[str] = None
    is_false_positive: bool = False

    timeline: list[TimelineEntry] = Field(default_factory=list)
    ai_summary: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def add_timeline_entry(self, description: str, source: str = "system", timestamp: datetime | None = None) -> None:
        entry_time = timestamp or datetime.now(timezone.utc)
        self.timeline.append(
            TimelineEntry(timestamp=entry_time, description=description, source=source)
        )
        self.updated_at = max(self.updated_at, entry_time)

    def to_row(self) -> dict[str, Any]:
        import json
        d = self.model_dump()
        d["created_at"] = self.created_at.isoformat()
        d["updated_at"] = self.updated_at.isoformat()
        for k in ("source_ips", "hosts", "related_alert_ids", "mitre_techniques",
                   "investigation_notes", "response_action_ids", "timeline", "metadata"):
            d[k] = json.dumps(d[k], default=str)
        return d
