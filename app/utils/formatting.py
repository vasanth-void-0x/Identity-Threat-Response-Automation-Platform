"""app/utils/formatting.py - Shared display formatting helpers for the dashboard."""

from __future__ import annotations

SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#27ae60",
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#888")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    return f"{emoji} **{severity.upper()}**"


def truncate(text: str | None, length: int = 60) -> str:
    if not text:
        return ""
    return text if len(text) <= length else text[: length - 1] + "…"


def format_timestamp(ts) -> str:
    if not isinstance(ts, str) or not ts:
        return "N/A"
    return ts.replace("T", " ").replace("Z", " UTC").split(".")[0]
