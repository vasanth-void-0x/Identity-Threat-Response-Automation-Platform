"""
database/connection.py
SQLite connection management. Database file is created automatically at
runtime (never committed to the repo). Uses row_factory for dict-like access
and enables foreign key / WAL pragmas for reliability under Streamlit's
multi-threaded execution model.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from core.config import load_config

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_local = threading.local()


def _resolve_db_path() -> Path:
    cfg = load_config()
    db_path = Path(cfg.database_path)
    if not db_path.is_absolute():
        db_path = PROJECT_ROOT / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


def get_connection() -> sqlite3.Connection:
    """Returns a thread-local SQLite connection, initializing the schema on first use."""
    if not hasattr(_local, "conn"):
        db_path = _resolve_db_path()
        is_new = not db_path.exists()
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        _local.conn = conn
        if is_new or _schema_missing(conn):
            initialize_schema(conn)

        # Local import to avoid a circular import (migrations depends on get_connection)
        from database.migrations import apply_migrations
        apply_migrations()
    return _local.conn


def _schema_missing(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'"
    ).fetchone()
    return row is None


def initialize_schema(conn: sqlite3.Connection) -> None:
    schema_path = Path(__file__).resolve().parent / "schema.sql"
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()


def close_connection() -> None:
    if hasattr(_local, "conn"):
        _local.conn.close()
        del _local.conn
