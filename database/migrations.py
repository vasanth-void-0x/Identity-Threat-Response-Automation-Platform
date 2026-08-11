"""
database/migrations.py
Lightweight schema versioning for a SQLite-backed lab project. `schema.sql`
is authoritative for brand-new databases; this module performs idempotent
ALTER TABLE / CREATE TABLE upgrades for databases created by earlier
versions of ITRAP, so existing installs don't need to be wiped to pick up
new features (approval workflow columns, Wazuh sync-state tables).
"""

from __future__ import annotations

import sqlite3

from core.logger import get_logger
from database.connection import get_connection

logger = get_logger(__name__)

CURRENT_SCHEMA_VERSION = "1.2.0"

_RESPONSE_ACTION_NEW_COLUMNS = [
    ("approved_by", "TEXT"),
    ("approved_at", "TEXT"),
    ("rejected_by", "TEXT"),
    ("rejected_at", "TEXT"),
    ("rejection_reason", "TEXT"),
    ("executed_at", "TEXT"),
]

_WAZUH_SYNC_STATE_TABLE = """
CREATE TABLE IF NOT EXISTS wazuh_sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_sync_at TEXT,
    last_sync_result TEXT,
    last_sync_error TEXT,
    events_retrieved INTEGER DEFAULT 0,
    events_ingested INTEGER DEFAULT 0,
    alerts_generated INTEGER DEFAULT 0,
    incidents_generated INTEGER DEFAULT 0
)
"""

_WAZUH_INGESTED_IDS_TABLE = """
CREATE TABLE IF NOT EXISTS wazuh_ingested_ids (
    fingerprint TEXT PRIMARY KEY,
    ingested_at TEXT
)
"""

_SPLUNK_SYNC_STATE_TABLE = _WAZUH_SYNC_STATE_TABLE.replace("wazuh_sync_state", "splunk_sync_state")
_SPLUNK_INGESTED_IDS_TABLE = _WAZUH_INGESTED_IDS_TABLE.replace("wazuh_ingested_ids", "splunk_ingested_ids")


def get_schema_version() -> str | None:
    conn = get_connection()
    row = conn.execute("SELECT value FROM settings WHERE key = 'schema_version'").fetchone()
    return row["value"] if row else None


def _existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def _migrate_response_actions_columns(conn: sqlite3.Connection) -> None:
    existing = _existing_columns(conn, "response_actions")
    for col_name, col_type in _RESPONSE_ACTION_NEW_COLUMNS:
        if col_name not in existing:
            conn.execute(f"ALTER TABLE response_actions ADD COLUMN {col_name} {col_type}")
            logger.info("Migration: added response_actions.%s", col_name)


def _migrate_wazuh_tables(conn: sqlite3.Connection) -> None:
    conn.execute(_WAZUH_SYNC_STATE_TABLE)
    conn.execute(_WAZUH_INGESTED_IDS_TABLE)
    conn.execute(_SPLUNK_SYNC_STATE_TABLE)
    conn.execute(_SPLUNK_INGESTED_IDS_TABLE)


def apply_migrations() -> None:
    conn = get_connection()
    version = get_schema_version()

    if version == CURRENT_SCHEMA_VERSION:
        return

    try:
        _migrate_response_actions_columns(conn)
        _migrate_wazuh_tables(conn)
        conn.commit()
    except sqlite3.OperationalError as exc:
        logger.warning("Migration step skipped/failed (likely already applied): %s", exc)

    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('schema_version', ?)",
        (CURRENT_SCHEMA_VERSION,),
    )
    conn.commit()
    logger.info("Database schema migrated to version %s", CURRENT_SCHEMA_VERSION)
