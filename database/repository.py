"""
database/repository.py
Repository layer providing clean, parameterized data-access functions for
events, alerts, incidents, users, response actions, and audit logs. All
queries use parameter binding (no string-formatted SQL).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from core.exceptions import DatabaseError
from core.logger import get_audit_logger, get_logger
from database.connection import get_connection
from models.alert import Alert
from models.event import NormalizedEvent
from models.incident import Incident
from models.response_action import ResponseAction

logger = get_logger(__name__)


# --- Events -------------------------------------------------------------------
def save_events(events: list[NormalizedEvent]) -> int:
    conn = get_connection()
    rows = [e.to_row() for e in events]
    if not rows:
        return 0
    cols = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in cols)
    col_list = ", ".join(cols)
    try:
        conn.executemany(
            f"INSERT OR REPLACE INTO events ({col_list}) VALUES ({placeholders})",
            [tuple(r[c] for c in cols) for r in rows],
        )
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        raise DatabaseError(f"Failed to save events: {exc}") from exc
    return len(rows)


def get_event_count() -> int:
    conn = get_connection()
    return conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]


def get_event_count_for_mode(mode: str) -> int:
    """Count evidence without mixing demo and live Splunk sources."""
    conn = get_connection()
    if mode == "Combined":
        return get_event_count()
    if mode == "Live Splunk":
        return conn.execute("SELECT COUNT(*) AS c FROM events WHERE source = ?", ("splunk_api",)).fetchone()["c"]
    return conn.execute("SELECT COUNT(*) AS c FROM events WHERE source != ?", ("splunk_api",)).fetchone()["c"]


def get_latest_event_for_mode(mode: str) -> dict | None:
    """Latest normalized event for the currently selected data source, or None.

    Uses the same source-separation rule as get_event_count_for_mode so the
    Live Event Monitor never mixes demo and Splunk-ingested evidence.
    """
    conn = get_connection()
    if mode == "Live Splunk":
        row = conn.execute(
            "SELECT * FROM events WHERE source = ? ORDER BY timestamp DESC LIMIT 1", ("splunk_api",)
        ).fetchone()
    elif mode == "Demo Data":
        row = conn.execute(
            "SELECT * FROM events WHERE source != ? ORDER BY timestamp DESC LIMIT 1", ("splunk_api",)
        ).fetchone()
    else:
        row = conn.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def get_event_sources(event_ids: list[str]) -> set[str]:
    if not event_ids:
        return set()
    placeholders = ",".join("?" for _ in event_ids)
    rows = get_connection().execute(
        f"SELECT DISTINCT source FROM events WHERE event_id IN ({placeholders})", event_ids
    ).fetchall()
    return {row["source"] for row in rows}


def get_incident_data_source(incident: dict) -> str:
    """Return a human-readable evidence source for report disclosure."""
    related_ids = set(incident.get("related_alert_ids") or [])
    alerts = [a for a in get_alerts(limit=10000) if a.get("alert_id") in related_ids]
    sources: set[str] = set()
    for alert in alerts:
        sources.update(get_event_sources(alert.get("event_ids") or []))
    has_live = "splunk_api" in sources
    has_demo = any(source != "splunk_api" for source in sources)
    if has_live and has_demo:
        return "Combined demo and live Splunk evidence"
    if has_live:
        return "Live Splunk lab evidence"
    return "Synthetic demo evidence"


# --- Alerts ---------------------------------------------------------------------
def save_alerts(alerts: list[Alert]) -> int:
    conn = get_connection()
    rows = [a.to_row() for a in alerts]
    if not rows:
        return 0
    cols = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in cols)
    col_list = ", ".join(cols)
    try:
        conn.executemany(
            f"INSERT OR REPLACE INTO alerts ({col_list}) VALUES ({placeholders})",
            [tuple(r[c] for c in cols) for r in rows],
        )
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        raise DatabaseError(f"Failed to save alerts: {exc}") from exc
    return len(rows)


def get_alerts(limit: int = 500, severity: str | None = None, user: str | None = None,
               status: str | None = None, source_ip: str | None = None,
               hostname: str | None = None, rule_name: str | None = None) -> list[dict]:
    conn = get_connection()
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list[Any] = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if user:
        query += " AND user = ?"
        params.append(user)
    if status:
        query += " AND status = ?"
        params.append(status)
    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    if hostname:
        query += " AND hostname = ?"
        params.append(hostname)
    if rule_name:
        query += " AND rule_name = ?"
        params.append(rule_name)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    return [_alert_row_to_dict(r) for r in rows]


def _alert_row_to_dict(row) -> dict:
    d = dict(row)
    for k in ("event_ids", "mitre_techniques", "contributions", "metadata"):
        try:
            d[k] = json.loads(d[k]) if d[k] else []
        except (json.JSONDecodeError, TypeError):
            d[k] = []
    return d


# --- Incidents ------------------------------------------------------------------
def save_incidents(incidents: list[Incident]) -> int:
    conn = get_connection()
    rows = [i.to_row() for i in incidents]
    if not rows:
        return 0
    cols = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in cols)
    col_list = ", ".join(cols)
    try:
        conn.executemany(
            f"INSERT OR REPLACE INTO incidents ({col_list}) VALUES ({placeholders})",
            [tuple(r[c] for c in cols) for r in rows],
        )
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        raise DatabaseError(f"Failed to save incidents: {exc}") from exc
    return len(rows)


def get_incidents(limit: int = 200, severity: str | None = None, status: str | None = None) -> list[dict]:
    conn = get_connection()
    query = "SELECT * FROM incidents WHERE 1=1"
    params: list[Any] = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    return [_incident_row_to_dict(r) for r in rows]


def get_incident(incident_id: str) -> dict | None:
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    return _incident_row_to_dict(row) if row else None


def _incident_row_to_dict(row) -> dict:
    d = dict(row)
    for k in ("source_ips", "hosts", "related_alert_ids", "mitre_techniques",
              "investigation_notes", "response_action_ids", "timeline", "metadata"):
        try:
            d[k] = json.loads(d[k]) if d[k] else []
        except (json.JSONDecodeError, TypeError):
            d[k] = []
    d["is_false_positive"] = bool(d.get("is_false_positive"))
    return d


def update_incident_status(incident_id: str, status: str, actor: str = "analyst") -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
        (status, datetime.now(timezone.utc).isoformat(), incident_id),
    )
    conn.commit()
    log_audit(actor=actor, action="incident_status_change", target=incident_id, details={"new_status": status})


def add_investigation_note(incident_id: str, note: str, author: str = "analyst") -> None:
    conn = get_connection()
    incident = get_incident(incident_id)
    if not incident:
        raise DatabaseError(f"Incident {incident_id} not found")
    notes = incident["investigation_notes"] + [f"[{author}] {note}"]
    conn.execute(
        "UPDATE incidents SET investigation_notes = ?, updated_at = ? WHERE incident_id = ?",
        (json.dumps(notes), datetime.now(timezone.utc).isoformat(), incident_id),
    )
    conn.commit()
    log_audit(actor=author, action="analyst_note_added", target=incident_id, details={"note": note})


def set_ai_summary(incident_id: str, summary: str) -> None:
    conn = get_connection()
    conn.execute("UPDATE incidents SET ai_summary = ? WHERE incident_id = ?", (summary, incident_id))
    conn.commit()


def mark_false_positive(incident_id: str, actor: str = "analyst") -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE incidents SET is_false_positive = 1, status = 'false_positive', updated_at = ? "
        "WHERE incident_id = ?",
        (datetime.now(timezone.utc).isoformat(), incident_id),
    )
    conn.commit()
    log_audit(actor=actor, action="marked_false_positive", target=incident_id, details={})


# --- Known IPs / devices (baseline for new_source_ip / new_device rules) --------
def load_known_ips() -> dict[str, set[str]]:
    conn = get_connection()
    rows = conn.execute("SELECT username, ip FROM known_ips").fetchall()
    result: dict[str, set[str]] = {}
    for r in rows:
        result.setdefault(r["username"], set()).add(r["ip"])
    return result


def save_known_ips(known_ips: dict[str, set[str]]) -> None:
    conn = get_connection()
    for user, ips in known_ips.items():
        for ip in ips:
            conn.execute(
                "INSERT OR IGNORE INTO known_ips (username, ip, first_seen) VALUES (?, ?, ?)",
                (user, ip, datetime.now(timezone.utc).isoformat()),
            )
    conn.commit()


def load_known_devices() -> dict[str, set[str]]:
    conn = get_connection()
    rows = conn.execute("SELECT username, device FROM known_devices").fetchall()
    result: dict[str, set[str]] = {}
    for r in rows:
        result.setdefault(r["username"], set()).add(r["device"])
    return result


def save_known_devices(known_devices: dict[str, set[str]]) -> None:
    conn = get_connection()
    for user, devices in known_devices.items():
        for device in devices:
            conn.execute(
                "INSERT OR IGNORE INTO known_devices (username, device, first_seen) VALUES (?, ?, ?)",
                (user, device, datetime.now(timezone.utc).isoformat()),
            )
    conn.commit()


def add_trusted_ip(username: str, ip: str, actor: str, reason: str) -> None:
    from core.validators import is_valid_ip
    username, actor, reason = username.strip(), actor.strip(), reason.strip()
    if not username or not actor or not reason or not is_valid_ip(ip):
        raise ValueError("Valid username, IP, analyst and reason are required")
    save_known_ips({username: {ip}})
    log_audit(actor, "trusted_ip_added", f"{username}:{ip}", {"reason": reason})


def remove_trusted_ip(username: str, ip: str, actor: str) -> None:
    if not username.strip() or not actor.strip():
        raise ValueError("Username and analyst are required")
    conn = get_connection()
    conn.execute("DELETE FROM known_ips WHERE username = ? AND ip = ?", (username.strip(), ip))
    conn.commit()
    log_audit(actor.strip(), "trusted_ip_removed", f"{username.strip()}:{ip}", {})


def add_trusted_device(username: str, device: str, actor: str, reason: str) -> None:
    username, device, actor, reason = username.strip(), device.strip(), actor.strip(), reason.strip()
    if not all((username, device, actor, reason)) or len(device) > 255:
        raise ValueError("Valid username, device, analyst and reason are required")
    save_known_devices({username: {device}})
    log_audit(actor, "trusted_device_added", f"{username}:{device}", {"reason": reason})


def remove_trusted_device(username: str, device: str, actor: str) -> None:
    if not username.strip() or not actor.strip():
        raise ValueError("Username and analyst are required")
    conn = get_connection()
    conn.execute("DELETE FROM known_devices WHERE username = ? AND device = ?", (username.strip(), device))
    conn.commit()
    log_audit(actor.strip(), "trusted_device_removed", f"{username.strip()}:{device}", {})


def get_trusted_baselines() -> dict[str, dict[str, list[str]]]:
    ips, devices = load_known_ips(), load_known_devices()
    users = sorted(set(ips) | set(devices))
    return {u: {"ips": sorted(ips.get(u, set())), "devices": sorted(devices.get(u, set()))} for u in users}


# --- Response actions -------------------------------------------------------------
def save_response_action(action: ResponseAction) -> None:
    conn = get_connection()
    row = action.to_row()
    cols = list(row.keys())
    placeholders = ", ".join("?" for _ in cols)
    col_list = ", ".join(cols)
    conn.execute(
        f"INSERT OR REPLACE INTO response_actions ({col_list}) VALUES ({placeholders})",
        tuple(row[c] for c in cols),
    )
    conn.commit()


def get_response_actions(incident_id: str | None = None, status: str | None = None) -> list[dict]:
    conn = get_connection()
    query = "SELECT * FROM response_actions WHERE 1=1"
    params: list[Any] = []
    if incident_id:
        query += " AND incident_id = ?"
        params.append(incident_id)
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY timestamp DESC"
    rows = conn.execute(query, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["rollback_info"] = json.loads(d["rollback_info"]) if d["rollback_info"] else {}
        except (json.JSONDecodeError, TypeError):
            d["rollback_info"] = {}
        result.append(d)
    return result


def get_response_action(action_id: str) -> dict | None:
    conn = get_connection()
    row = conn.execute("SELECT * FROM response_actions WHERE action_id = ?", (action_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["rollback_info"] = json.loads(d["rollback_info"]) if d["rollback_info"] else {}
    except (json.JSONDecodeError, TypeError):
        d["rollback_info"] = {}
    return d


def update_response_action_status(action_id: str, **fields: Any) -> None:
    """Generic field updater used by the approval workflow (approve/reject/execute transitions)."""
    if not fields:
        return
    conn = get_connection()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [action_id]
    conn.execute(f"UPDATE response_actions SET {set_clause} WHERE action_id = ?", values)
    conn.commit()


# --- Audit log --------------------------------------------------------------------
def log_audit(actor: str, action: str, target: str, details: dict) -> None:
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_logs (timestamp, actor, action, target, details) VALUES (?, ?, ?, ?, ?)",
        (datetime.now(timezone.utc).isoformat(), actor, action, target, json.dumps(details)),
    )
    conn.commit()
    get_audit_logger().info("actor=%s action=%s target=%s details=%s", actor, action, target, details)


def get_audit_logs(limit: int = 200) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d["details"]) if d["details"] else {}
        except (json.JSONDecodeError, TypeError):
            d["details"] = {}
        result.append(d)
    return result


# --- Wazuh API sync state ----------------------------------------------------------
def save_wazuh_sync_state(result: dict[str, Any]) -> None:
    conn = get_connection()
    conn.execute(
        "INSERT INTO wazuh_sync_state "
        "(id, last_sync_at, last_sync_result, last_sync_error, events_retrieved, "
        "events_ingested, alerts_generated, incidents_generated) "
        "VALUES (1, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "last_sync_at = excluded.last_sync_at, last_sync_result = excluded.last_sync_result, "
        "last_sync_error = excluded.last_sync_error, events_retrieved = excluded.events_retrieved, "
        "events_ingested = excluded.events_ingested, alerts_generated = excluded.alerts_generated, "
        "incidents_generated = excluded.incidents_generated",
        (
            result.get("synced_at"),
            "success" if result.get("success") else "failed",
            result.get("error"),
            result.get("events_retrieved", 0),
            result.get("events_ingested", 0),
            result.get("alerts_generated", 0),
            result.get("incidents_generated", 0),
        ),
    )
    conn.commit()


def get_wazuh_sync_state() -> dict | None:
    conn = get_connection()
    row = conn.execute("SELECT * FROM wazuh_sync_state WHERE id = 1").fetchone()
    return dict(row) if row else None


def is_wazuh_fingerprint_seen(fingerprint: str) -> bool:
    conn = get_connection()
    row = conn.execute(
        "SELECT 1 FROM wazuh_ingested_ids WHERE fingerprint = ?", (fingerprint,)
    ).fetchone()
    return row is not None


def mark_wazuh_fingerprints_seen(fingerprints: list[str]) -> None:
    if not fingerprints:
        return
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT OR IGNORE INTO wazuh_ingested_ids (fingerprint, ingested_at) VALUES (?, ?)",
        [(fp, now) for fp in fingerprints],
    )
    conn.commit()


# --- Splunk API sync state -------------------------------------------------------
def save_splunk_sync_state(result: dict[str, Any]) -> None:
    conn = get_connection()
    conn.execute(
        "INSERT INTO splunk_sync_state (id, last_sync_at, last_sync_result, last_sync_error, "
        "events_retrieved, events_ingested, alerts_generated, incidents_generated) "
        "VALUES (1, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
        "last_sync_at=excluded.last_sync_at, last_sync_result=excluded.last_sync_result, "
        "last_sync_error=excluded.last_sync_error, events_retrieved=excluded.events_retrieved, "
        "events_ingested=excluded.events_ingested, alerts_generated=excluded.alerts_generated, "
        "incidents_generated=excluded.incidents_generated",
        (result.get("synced_at"), "success" if result.get("success") else "failed", result.get("error"),
         result.get("events_retrieved", 0), result.get("events_ingested", 0),
         result.get("alerts_generated", 0), result.get("incidents_generated", 0)),
    )
    conn.commit()


def get_splunk_sync_state() -> dict | None:
    row = get_connection().execute("SELECT * FROM splunk_sync_state WHERE id=1").fetchone()
    return dict(row) if row else None


def is_splunk_fingerprint_seen(fingerprint: str) -> bool:
    return get_connection().execute(
        "SELECT 1 FROM splunk_ingested_ids WHERE fingerprint=?", (fingerprint,)
    ).fetchone() is not None


def mark_splunk_fingerprints_seen(fingerprints: list[str]) -> None:
    if not fingerprints:
        return
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT OR IGNORE INTO splunk_ingested_ids (fingerprint, ingested_at) VALUES (?, ?)",
        [(fp, now) for fp in fingerprints],
    )
    conn.commit()


# --- Dashboard aggregate stats ------------------------------------------------------
def get_overview_stats() -> dict:
    conn = get_connection()
    stats = {}
    stats["total_events"] = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    stats["total_alerts"] = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]

    for sev in ("low", "medium", "high", "critical"):
        stats[f"{sev}_incidents"] = conn.execute(
            "SELECT COUNT(*) c FROM incidents WHERE severity = ?", (sev,)
        ).fetchone()["c"]

    stats["open_incidents"] = conn.execute(
        "SELECT COUNT(*) c FROM incidents WHERE status NOT IN ('resolved', 'false_positive')"
    ).fetchone()["c"]
    stats["contained_incidents"] = conn.execute(
        "SELECT COUNT(*) c FROM incidents WHERE status = 'contained'"
    ).fetchone()["c"]

    mean_row = conn.execute("SELECT AVG(risk_score) a FROM incidents").fetchone()
    stats["mean_risk_score"] = round(mean_row["a"], 1) if mean_row["a"] else 0

    stats["top_users"] = [
        dict(r) for r in conn.execute(
            "SELECT user, COUNT(*) alert_count FROM alerts WHERE user IS NOT NULL "
            "GROUP BY user ORDER BY alert_count DESC LIMIT 5"
        ).fetchall()
    ]
    stats["top_source_ips"] = [
        dict(r) for r in conn.execute(
            "SELECT source_ip, COUNT(*) alert_count FROM alerts WHERE source_ip IS NOT NULL "
            "GROUP BY source_ip ORDER BY alert_count DESC LIMIT 5"
        ).fetchall()
    ]
    return stats
