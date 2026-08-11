"""models/user_profile.py - Tracks known baseline behavior per user (IPs, devices)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class UserProfile(BaseModel):
    username: str
    display_name: Optional[str] = None
    department: Optional[str] = None
    is_privileged: bool = False
    known_ips: list[str] = Field(default_factory=list)
    known_devices: list[str] = Field(default_factory=list)
    known_countries: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_location: Optional[dict] = None
    last_login_time: Optional[datetime] = None
