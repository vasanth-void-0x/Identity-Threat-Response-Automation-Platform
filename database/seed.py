"""
database/seed.py
Loads sample_data/*.json into the platform: users, known devices, benign
events, and all attack scenarios, then runs detection + correlation and
persists everything. Used by seed_demo.py / scripts/seed_demo.ps1.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.logger import get_logger
from database import repository
from database.connection import get_connection
from database.migrations import apply_migrations
from detection_engine.engine import DetectionEngine
from parsers.json_parser import parse_json_file

logger = get_logger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DATA_DIR = PROJECT_ROOT / "sample_data"

SCENARIO_FILES = [
    "benign_events.json",
    "brute_force_events.json",
    "impossible_travel_events.json",
    "privilege_events.json",
    "powershell_events.json",
    "correlated_attack.json",
]


def clear_demo_data() -> None:
    conn = get_connection()
    for table in ("events", "alerts", "incidents", "known_ips", "known_devices",
                  "response_actions", "analyst_notes", "audit_logs", "splunk_ingested_ids"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    logger.info("Cleared existing demo data")


def seed_users_and_devices() -> None:
    conn = get_connection()

    users_path = SAMPLE_DATA_DIR / "users.json"
    known_ips: dict[str, set[str]] = {}

    if users_path.exists():
        with open(users_path, "r", encoding="utf-8") as f:
            users = json.load(f)
        for u in users:
            conn.execute(
                "INSERT OR REPLACE INTO users "
                "(username, display_name, department, is_privileged, known_ips, known_devices, "
                "known_countries, first_seen, last_seen, last_location, last_login_time) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    u["username"], u.get("display_name"), u.get("department"),
                    int(u.get("is_privileged", False)),
                    json.dumps(u.get("known_ips", [])), json.dumps(u.get("known_devices", [])),
                    json.dumps(u.get("known_countries", [])),
                    u.get("first_seen", ""), u.get("last_seen", ""),
                    json.dumps(u.get("last_location")), u.get("last_login_time"),
                ),
            )
            if u.get("known_ips"):
                known_ips[u["username"]] = set(u["known_ips"])
        conn.commit()
        logger.info("Seeded %d user profiles", len(users))

        # Bug fix: known_ips were previously only stored as a JSON blob on the
        # users row and never inserted into the dedicated known_ips table that
        # detection_engine.engine actually reads as the new_source_ip baseline.
        if known_ips:
            repository.save_known_ips(known_ips)
            total_ips = sum(len(v) for v in known_ips.values())
            logger.info("Seeded %d known IP(s) across %d user(s) into known_ips baseline",
                        total_ips, len(known_ips))

    devices_path = SAMPLE_DATA_DIR / "known_devices.json"
    if devices_path.exists():
        with open(devices_path, "r", encoding="utf-8") as f:
            device_map = json.load(f)
        known_devices = {user: set(devices) for user, devices in device_map.items()}
        repository.save_known_devices(known_devices)
        logger.info("Seeded known devices for %d users", len(device_map))


def seed_demo_data(clear_first: bool = True) -> dict:
    apply_migrations()

    if clear_first:
        clear_demo_data()

    seed_users_and_devices()

    all_events = []
    for filename in SCENARIO_FILES:
        path = SAMPLE_DATA_DIR / filename
        if not path.exists():
            logger.warning("Sample data file missing, skipping: %s", filename)
            continue
        events = parse_json_file(path, source=filename.replace(".json", ""))
        all_events.extend(events)

    repository.save_events(all_events)
    logger.info("Seeded %d normalized events", len(all_events))

    engine = DetectionEngine()
    alerts, incidents = engine.run(all_events)

    repository.save_alerts(alerts)
    repository.save_incidents(incidents)

    logger.info("Demo seed complete: %d events, %d alerts, %d incidents",
                len(all_events), len(alerts), len(incidents))

    return {
        "events": len(all_events),
        "alerts": len(alerts),
        "incidents": len(incidents),
    }


if __name__ == "__main__":
    summary = seed_demo_data()
    print(f"Seeded: {summary['events']} events, {summary['alerts']} alerts, {summary['incidents']} incidents")
