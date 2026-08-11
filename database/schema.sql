-- database/schema.sql
-- Identity Threat Response Automation Platform - SQLite schema
-- Created automatically at runtime. No binary DB file is committed to the repo.

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT,
    provider TEXT,
    channel TEXT,
    event_type TEXT,
    event_code TEXT,
    user TEXT,
    domain TEXT,
    target_user TEXT,
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    hostname TEXT,
    device_id TEXT,
    logon_type TEXT,
    process_name TEXT,
    process_id TEXT,
    parent_process TEXT,
    command_line TEXT,
    status TEXT,
    failure_reason TEXT,
    country TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    raw_event TEXT,
    metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    rule_name TEXT,
    title TEXT,
    description TEXT,
    created_at TEXT,
    user TEXT,
    source_ip TEXT,
    hostname TEXT,
    device_id TEXT,
    event_ids TEXT,
    mitre_techniques TEXT,
    base_score INTEGER,
    contributions TEXT,
    final_score INTEGER,
    severity TEXT,
    status TEXT,
    incident_id TEXT,
    explanation TEXT,
    metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    created_at TEXT,
    updated_at TEXT,
    user TEXT,
    source_ips TEXT,
    hosts TEXT,
    related_alert_ids TEXT,
    mitre_techniques TEXT,
    risk_score INTEGER,
    severity TEXT,
    status TEXT,
    investigation_notes TEXT,
    response_action_ids TEXT,
    analyst_decision TEXT,
    is_false_positive INTEGER,
    timeline TEXT,
    ai_summary TEXT,
    metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    display_name TEXT,
    department TEXT,
    is_privileged INTEGER,
    known_ips TEXT,
    known_devices TEXT,
    known_countries TEXT,
    first_seen TEXT,
    last_seen TEXT,
    last_location TEXT,
    last_login_time TEXT
);

CREATE TABLE IF NOT EXISTS known_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip TEXT,
    first_seen TEXT,
    UNIQUE(username, ip)
);

CREATE TABLE IF NOT EXISTS known_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    device TEXT,
    first_seen TEXT,
    UNIQUE(username, device)
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip TEXT PRIMARY KEY,
    data TEXT,
    cached_at REAL
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id TEXT PRIMARY KEY,
    incident_id TEXT,
    action_type TEXT,
    target TEXT,
    requested_by TEXT,
    mode TEXT,
    timestamp TEXT,
    result TEXT,
    status TEXT,
    error TEXT,
    rollback_info TEXT,
    approved_by TEXT,
    approved_at TEXT,
    rejected_by TEXT,
    rejected_at TEXT,
    rejection_reason TEXT,
    executed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_response_actions_incident ON response_actions(incident_id);

CREATE TABLE IF NOT EXISTS analyst_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    note TEXT,
    author TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    actor TEXT,
    action TEXT,
    target TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

CREATE TABLE IF NOT EXISTS wazuh_sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_sync_at TEXT,
    last_sync_result TEXT,
    last_sync_error TEXT,
    events_retrieved INTEGER DEFAULT 0,
    events_ingested INTEGER DEFAULT 0,
    alerts_generated INTEGER DEFAULT 0,
    incidents_generated INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wazuh_ingested_ids (
    fingerprint TEXT PRIMARY KEY,
    ingested_at TEXT
);

CREATE TABLE IF NOT EXISTS splunk_sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_sync_at TEXT,
    last_sync_result TEXT,
    last_sync_error TEXT,
    events_retrieved INTEGER DEFAULT 0,
    events_ingested INTEGER DEFAULT 0,
    alerts_generated INTEGER DEFAULT 0,
    incidents_generated INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS splunk_ingested_ids (
    fingerprint TEXT PRIMARY KEY,
    ingested_at TEXT
);
