"""tests/conftest.py - Shared pytest fixtures. Uses a temp SQLite DB, no network access."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(autouse=True)
def isolated_test_db(tmp_path, monkeypatch):
    """Every test gets a fresh temp SQLite database and reloaded config."""
    db_path = tmp_path / "test_itrap.db"
    monkeypatch.setenv("ITRAP_TEST_DB_PATH", str(db_path))

    from core import config as config_module
    config_module._config_instance = None

    import database.connection as conn_module
    if hasattr(conn_module._local, "conn"):
        conn_module._local.conn.close()
        del conn_module._local.conn

    original_resolve = conn_module._resolve_db_path
    monkeypatch.setattr(conn_module, "_resolve_db_path", lambda: db_path)

    yield

    if hasattr(conn_module._local, "conn"):
        conn_module._local.conn.close()
        del conn_module._local.conn


def make_raw_event(**overrides):
    base = {
        "event_code": "4624",
        "timestamp": "2026-07-20T09:00:00Z",
        "user": "alice",
        "source_ip": "192.0.2.10",
        "hostname": "WKS-ALICE-01",
        "status": "success",
    }
    base.update(overrides)
    return base
