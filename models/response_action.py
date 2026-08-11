"""
models/response_action.py
Record of a (simulated or real) automated response action, including the
full approval workflow lifecycle for real actions.

Status lifecycle:
  pending_approval -> approved -> executed
  pending_approval -> rejected
  (simulation-mode actions skip straight to "executed" - no real system
  change occurs, so no approval gate is required)
  any -> failed (policy violation or execution error)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

VALID_STATUSES = {"pending_approval", "approved", "rejected", "executed", "failed", "rolled_back"}


class ResponseAction(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    action_type: str  # block_ip | disable_account | isolate_host | kill_process | create_ticket | ...
    target: str
    requested_by: str = "system"
    mode: str = "simulation"  # simulation | real
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    result: str = ""
    status: str = "pending_approval"  # see VALID_STATUSES above
    error: Optional[str] = None
    rollback_info: dict[str, Any] = Field(default_factory=dict)

    # Approval workflow fields (only meaningful for mode="real")
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejected_by: Optional[str] = None
    rejected_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    executed_at: Optional[datetime] = None

    def to_row(self) -> dict[str, Any]:
        import json
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        d["rollback_info"] = json.dumps(d["rollback_info"])
        d["approved_at"] = self.approved_at.isoformat() if self.approved_at else None
        d["rejected_at"] = self.rejected_at.isoformat() if self.rejected_at else None
        d["executed_at"] = self.executed_at.isoformat() if self.executed_at else None
        return d
