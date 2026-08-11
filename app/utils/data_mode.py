"""Source-aware filtering for Demo, Live Splunk, and Combined workspaces."""

from __future__ import annotations

from database import repository

DATA_MODES = ("Live Splunk", "Demo Data", "Combined")


def is_live_alert(alert: dict) -> bool:
    return "splunk_api" in repository.get_event_sources(alert.get("event_ids") or [])


def filter_alerts(alerts: list[dict], mode: str) -> list[dict]:
    if mode == "Combined":
        return alerts
    want_live = mode == "Live Splunk"
    return [alert for alert in alerts if is_live_alert(alert) is want_live]


def filter_incidents(incidents: list[dict], alerts: list[dict], mode: str) -> list[dict]:
    if mode == "Combined":
        return incidents
    live_alert_ids = {a["alert_id"] for a in alerts if is_live_alert(a)}
    want_live = mode == "Live Splunk"
    selected = []
    for incident in incidents:
        related = set(incident.get("related_alert_ids") or [])
        if bool(related & live_alert_ids) is want_live:
            selected.append(incident)
    return selected


def overview_stats(mode: str, alerts: list[dict], incidents: list[dict]) -> dict:
    open_statuses = {"new", "investigating", "contained"}
    scores = [float(i.get("risk_score") or 0) for i in incidents]
    return {
        "total_events": repository.get_event_count_for_mode(mode),
        "total_alerts": len(alerts),
        "open_incidents": sum(i.get("status") in open_statuses for i in incidents),
        "critical_incidents": sum(i.get("severity") == "critical" for i in incidents),
        "high_incidents": sum(i.get("severity") == "high" for i in incidents),
        "mean_risk_score": round(sum(scores) / len(scores), 1) if scores else 0,
    }


# Same bucket boundaries as the incident risk gauge (app/components/charts.py)
# so the Threat Level badge and any per-incident gauge always agree.
RISK_LEVEL_BOUNDS = (("LOW", 0, 29), ("MEDIUM", 30, 59), ("HIGH", 60, 79), ("CRITICAL", 80, 100))


def risk_level_for_score(score: float) -> str:
    for label, low, high in RISK_LEVEL_BOUNDS:
        if low <= score <= high:
            return label
    return "CRITICAL" if score > 100 else "LOW"


def threat_level(incidents: list[dict]) -> dict:
    """Dynamic overall threat level from the currently filtered incidents.

    Uses the single highest active risk score as the headline figure (the
    worst live case drives analyst attention), with the mean kept alongside
    for context.
    """
    scores = [float(i.get("risk_score") or 0) for i in incidents]
    highest = max(scores) if scores else 0
    mean = round(sum(scores) / len(scores), 1) if scores else 0
    return {
        "level": risk_level_for_score(highest),
        "highest_score": round(highest, 1),
        "mean_score": mean,
        "critical_count": sum(i.get("severity") == "critical" for i in incidents),
        "high_count": sum(i.get("severity") == "high" for i in incidents),
    }


def latest_incident(incidents: list[dict]) -> dict | None:
    if not incidents:
        return None
    return max(incidents, key=lambda i: i.get("created_at") or "")


def bucketed_counts(items: list[dict], *, time_field: str = "created_at", buckets: int = 8) -> list[float]:
    """Equal-width count buckets across the actual observed time range.

    Used only for restrained metric-card sparklines. Bucketing by the data's
    own min/max range (rather than wall-clock "now") keeps trends meaningful
    for both historical demo scenarios and live-ingested evidence.
    """
    import pandas as pd

    if not items:
        return []
    timestamps = pd.to_datetime(
        [i.get(time_field) for i in items], format="mixed", utc=True, errors="coerce"
    ).dropna()
    if len(timestamps) < 2 or (timestamps.max() - timestamps.min()).total_seconds() <= 0:
        return []
    binned = pd.cut(timestamps, bins=buckets, include_lowest=True)
    counts = pd.Series(binned).value_counts().sort_index()
    return counts.astype(float).tolist()
