"""
models/event.py
Normalized event schema - the common data model every parser (JSON, CSV, Windows
Event Log XML, Sysmon, PowerShell, Splunk, Wazuh) converts raw source data into.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class NormalizedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime

    source: str = "unknown"          # e.g. "sample_data", "windows_event_log", "sysmon", "splunk"
    provider: str = "windows"        # windows | sysmon | okta | azuread | generic
    channel: str = "Security"

    event_type: str = "unknown"      # logon_success | logon_failure | process_creation | ...
    event_code: str = ""             # raw Windows/Sysmon event ID, e.g. "4625"

    user: Optional[str] = None
    domain: Optional[str] = None
    target_user: Optional[str] = None

    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

    hostname: Optional[str] = None
    device_id: Optional[str] = None
    logon_type: Optional[str] = None

    process_name: Optional[str] = None
    process_id: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None

    status: str = "unknown"          # success | failure | pending | unknown
    failure_reason: Optional[str] = None

    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    raw_event: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _coerce_timestamp(cls, v):
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str):
            from core.validators import parse_timestamp
            return parse_timestamp(v)
        raise ValueError(f"Cannot coerce timestamp from value: {v!r}")

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})

    def to_row(self) -> dict[str, Any]:
        """Flattened dict suitable for SQLite insertion."""
        import json
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        d["raw_event"] = json.dumps(d["raw_event"])
        d["metadata"] = json.dumps(d["metadata"])
        return d
