"""models/alert.py - Alert produced by a single detection rule firing."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class RiskContribution(BaseModel):
    reason: str
    points: int


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_name: str
    title: str
    description: str

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    user: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    device_id: Optional[str] = None

    event_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    base_score: int = 0
    contributions: list[RiskContribution] = Field(default_factory=list)
    final_score: int = 0
    severity: str = "low"

    status: str = "new"
    incident_id: Optional[str] = None

    explanation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        import json
        d = self.model_dump()
        d["created_at"] = self.created_at.isoformat()
        d["event_ids"] = json.dumps(d["event_ids"])
        d["mitre_techniques"] = json.dumps(d["mitre_techniques"])
        d["contributions"] = json.dumps(d["contributions"])
        d["metadata"] = json.dumps(d["metadata"])
        return d
