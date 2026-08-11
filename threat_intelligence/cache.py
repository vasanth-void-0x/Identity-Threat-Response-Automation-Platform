"""
threat_intelligence/cache.py
SQLite-backed cache for threat intelligence lookups, to respect provider
rate limits and avoid repeated external calls for the same IP.
"""

from __future__ import annotations

import json
import time

from database.connection import get_connection


def get_cached(ip: str, ttl_seconds: int) -> dict | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT data, cached_at FROM threat_intel_cache WHERE ip = ?", (ip,)
    ).fetchone()
    if not row:
        return None
    if time.time() - row["cached_at"] > ttl_seconds:
        return None
    return json.loads(row["data"])


def set_cached(ip: str, data: dict) -> None:
    conn = get_connection()
    conn.execute(
        "INSERT INTO threat_intel_cache (ip, data, cached_at) VALUES (?, ?, ?) "
        "ON CONFLICT(ip) DO UPDATE SET data = excluded.data, cached_at = excluded.cached_at",
        (ip, json.dumps(data), time.time()),
    )
    conn.commit()
