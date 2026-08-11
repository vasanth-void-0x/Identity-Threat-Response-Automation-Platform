"""core/validators.py - Shared validation helpers for IPs, timestamps, and config values."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

_WINDOWS_TIMEZONE_SUFFIXES = {
    "India Standard Time": timezone(timedelta(hours=5, minutes=30)),
    "UTC": timezone.utc,
}


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except (ValueError, TypeError):
        return False


def is_reserved_demo_ip(value: str) -> bool:
    """True for documentation/demo IP ranges (RFC 5737) used in sample data."""
    from core.constants import RESERVED_DEMO_IP_RANGES

    return any(value.startswith(prefix) for prefix in RESERVED_DEMO_IP_RANGES)


def parse_timestamp(value: str) -> datetime:
    """Parses timestamps and always returns a UTC-aware datetime."""
    value = value.strip()

    for suffix, tzinfo in _WINDOWS_TIMEZONE_SUFFIXES.items():
        marker = f" {suffix}"
        if value.endswith(marker):
            local_value = value[:-len(marker)].strip()
            dt = datetime.fromisoformat(local_value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=tzinfo)
            return dt.astimezone(timezone.utc)

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def is_business_hours(dt: datetime, start_hour: int = 9, end_hour: int = 18) -> bool:
    """Weekday check, naive business-hours heuristic (local server time assumed UTC)."""
    if dt.weekday() >= 5:
        return False
    return start_hour <= dt.hour < end_hour


def safe_get(d: dict, key: str, default=None):
    v = d.get(key, default)
    return default if v is None else v
