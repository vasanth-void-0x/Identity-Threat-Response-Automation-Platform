"""
detection_engine/correlation.py
Groups related alerts (same user / source IP / hostname / device within a
configurable time window) into a single Incident, rather than surfacing
many disconnected alerts for what is really one attack sequence.
"""

from __future__ import annotations

from datetime import timedelta

from core.config import load_config
from detection_engine.risk_scoring import score_incident
from models.alert import Alert
from models.incident import Incident


def _shares_correlation_key(a: Alert, b: Alert) -> bool:
    if a.user and b.user and a.user == b.user:
        return True
    if a.source_ip and b.source_ip and a.source_ip == b.source_ip:
        return True
    if a.hostname and b.hostname and a.hostname == b.hostname:
        return True
    if a.device_id and b.device_id and a.device_id == b.device_id:
        return True
    return False


def correlate_alerts(alerts: list[Alert]) -> list[Incident]:
    """
    Union-find style grouping: alerts are merged into the same incident cluster
    if they share a correlation key (user/IP/host/device) and fall within the
    configured correlation time window.
    """
    if not alerts:
        return []

    cfg = load_config()
    window = timedelta(minutes=cfg.correlation_window_minutes)

    sorted_alerts = sorted(alerts, key=lambda a: a.created_at)
    clusters: list[list[Alert]] = []

    for alert in sorted_alerts:
        placed = False
        for cluster in clusters:
            last = cluster[-1]
            if _shares_correlation_key(alert, last) and (alert.created_at - cluster[0].created_at) <= window:
                cluster.append(alert)
                placed = True
                break
            # also check against any member, not just the last, for multi-stage sequences
            if any(_shares_correlation_key(alert, member) for member in cluster) and \
                    (alert.created_at - cluster[0].created_at) <= window:
                cluster.append(alert)
                placed = True
                break
        if not placed:
            clusters.append([alert])

    incidents: list[Incident] = []
    for cluster in clusters:
        incidents.append(_build_incident(cluster))
    return incidents


def _build_incident(cluster: list[Alert]) -> Incident:
    users = {a.user for a in cluster if a.user}
    ips = {a.source_ip for a in cluster if a.source_ip}
    hosts = {a.hostname for a in cluster if a.hostname}
    techniques = sorted({t for a in cluster for t in a.mitre_techniques})
    distinct_rules = {a.rule_name for a in cluster}

    rule_scores: dict[str, int] = {}
    for a in cluster:
        rule_scores[a.rule_name] = max(rule_scores.get(a.rule_name, 0), a.final_score)

    incident_score, severity = score_incident(rule_scores)

    primary_user = next(iter(users)) if len(users) == 1 else (
        f"{len(users)} users" if users else None
    )

    title = _generate_title(cluster, users, distinct_rules)

    alert_timestamps = [a.created_at for a in cluster]
    earliest = min(alert_timestamps)
    latest = max(alert_timestamps)

    incident = Incident(
        title=title,
        description=_generate_description(cluster),
        user=primary_user if isinstance(primary_user, str) and "users" not in primary_user else (
            next(iter(users)) if users else None
        ),
        source_ips=sorted(ips),
        hosts=sorted(hosts),
        related_alert_ids=[a.alert_id for a in cluster],
        mitre_techniques=techniques,
        risk_score=incident_score,
        severity=severity,
        status="new",
        created_at=earliest,
        updated_at=latest,
    )

    for a in sorted(cluster, key=lambda x: x.created_at):
        incident.add_timeline_entry(
            f"[{a.rule_name}] {a.title} (score: {a.final_score})", source="system",
            timestamp=a.created_at,
        )
        a.incident_id = incident.incident_id

    return incident


def _generate_title(cluster: list[Alert], users: set, distinct_rules: set) -> str:
    if len(cluster) == 1:
        return cluster[0].title

    user_part = next(iter(users)) if len(users) == 1 else "multiple users"
    if len(distinct_rules) >= 3:
        return f"Multi-stage identity attack sequence involving {user_part}"
    return f"Correlated identity threat activity involving {user_part}"


def _generate_description(cluster: list[Alert]) -> str:
    rule_names = sorted({a.rule_name for a in cluster})
    return (
        f"This incident correlates {len(cluster)} alert(s) across {len(rule_names)} "
        f"detection rule(s): {', '.join(rule_names)}. Review the timeline for the "
        "full attack sequence."
    )
