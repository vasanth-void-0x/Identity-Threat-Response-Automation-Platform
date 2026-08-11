"""threat_intelligence/reputation.py - Shared reputation classification helpers."""

from __future__ import annotations

REPUTATION_LEVELS = ["clean", "unknown", "suspicious", "malicious"]


def is_actionable(reputation: str) -> bool:
    """Whether this reputation level should influence risk scoring / response."""
    return reputation in ("suspicious", "malicious")


def combine_reputation(*reputations: str) -> str:
    """Returns the worst (highest-severity) reputation from a set of lookups."""
    order = {"clean": 0, "unknown": 1, "suspicious": 2, "malicious": 3}
    worst = max(reputations, key=lambda r: order.get(r, 0), default="unknown")
    return worst
