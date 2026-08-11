"""
core/config.py
Central configuration loader for the Identity Threat Response Automation Platform.

Loads config.yaml + risk_weights.yaml + response_policy.yaml + detection_rules.yaml
and merges in environment variables (via python-dotenv) for secrets.

Never hardcodes secrets. All API keys are optional and default to empty/disabled.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

from core.exceptions import ConfigurationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "configs"

load_dotenv(PROJECT_ROOT / ".env", override=False)


class ThreatIntelConfig(BaseModel):
    provider: str = "mock"  # mock | virustotal | abuseipdb
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    geoip_provider: str = "mock"
    cache_ttl_seconds: int = 3600
    request_timeout_seconds: int = 5
    max_retries: int = 2


class AIConfig(BaseModel):
    provider: str = "mock"  # mock | groq
    groq_api_key: str = ""
    model: str = "llama-3.3-70b-versatile"


class WazuhAPIConfig(BaseModel):
    """
    Wazuh REST API connection settings. Read ONLY from environment variables
    (never from YAML, never hardcoded) since these include credentials.
    All fields default to empty/safe values - the platform runs fully in
    offline demo mode when unset.
    """
    api_url: str = ""
    username: str = ""
    password: str = ""
    verify_ssl: bool = True
    request_timeout_seconds: int = 10

    @property
    def is_configured(self) -> bool:
        return bool(self.api_url and self.username and self.password)


class SplunkAPIConfig(BaseModel):
    """Token-authenticated Splunk management REST API settings."""
    url: str = "https://localhost:8089"
    token: str = ""
    index: str = "main"
    sourcetype: str = "WinEventLog:Security"
    verify_ssl: bool = True
    request_timeout_seconds: int = 30
    max_events: int = 500

    @property
    def is_configured(self) -> bool:
        return bool(self.url and self.token and self.index and self.sourcetype)


class ResponsePolicyConfig(BaseModel):
    simulation_mode: bool = True
    require_analyst_approval: bool = True
    allow_private_ip_blocking: bool = False
    allow_localhost_blocking: bool = False
    minimum_severity_threshold: str = "high"
    protected_users: list[str] = Field(default_factory=lambda: ["administrator", "system", "svc_backup"])
    protected_hosts: list[str] = Field(default_factory=list)
    protected_networks: list[str] = Field(default_factory=lambda: ["10.0.0.0/8", "127.0.0.0/8"])
    action_allowlist: list[str] = Field(
        default_factory=lambda: [
            "block_ip", "disable_account", "isolate_host",
            "kill_process", "create_ticket", "email_alert",
            "slack_alert", "flag_for_review",
        ]
    )


class AppConfig(BaseModel):
    app_name: str = "Identity Threat Response Automation Platform"
    environment: str = "lab"
    database_path: str = "database/itrap.db"
    log_level: str = "INFO"
    log_dir: str = "logs"
    correlation_window_minutes: int = 30
    report_output_dir: str = "reports_output"
    email_enabled: bool = False
    slack_enabled: bool = False
    email_smtp_host: str = ""
    email_smtp_port: int = 587
    email_from: str = ""
    email_to: str = ""
    slack_webhook_url: str = ""

    threat_intelligence: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    response_policy: ResponsePolicyConfig = Field(default_factory=ResponsePolicyConfig)
    wazuh_api: WazuhAPIConfig = Field(default_factory=WazuhAPIConfig)
    splunk_api: SplunkAPIConfig = Field(default_factory=SplunkAPIConfig)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ConfigurationError(f"Invalid log_level '{v}'. Must be one of {allowed}")
        return v.upper()


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Overlay secret/env-controlled values without ever hardcoding them in YAML."""
    ti = data.setdefault("threat_intelligence", {})
    ti["virustotal_api_key"] = os.getenv("VIRUSTOTAL_API_KEY", ti.get("virustotal_api_key", ""))
    ti["abuseipdb_api_key"] = os.getenv("ABUSEIPDB_API_KEY", ti.get("abuseipdb_api_key", ""))

    ai = data.setdefault("ai", {})
    ai["groq_api_key"] = os.getenv("GROQ_API_KEY", ai.get("groq_api_key", ""))

    data["slack_webhook_url"] = os.getenv("SLACK_WEBHOOK_URL", data.get("slack_webhook_url", ""))
    data["email_smtp_host"] = os.getenv("EMAIL_SMTP_HOST", data.get("email_smtp_host", ""))

    # Wazuh REST API - environment-variable-only, never read from YAML
    wazuh = data.setdefault("wazuh_api", {})
    wazuh["api_url"] = os.getenv("WAZUH_API_URL", "")
    wazuh["username"] = os.getenv("WAZUH_API_USERNAME", "")
    wazuh["password"] = os.getenv("WAZUH_API_PASSWORD", "")
    wazuh["verify_ssl"] = os.getenv("WAZUH_VERIFY_SSL", "true").lower() != "false"
    try:
        wazuh["request_timeout_seconds"] = int(os.getenv("WAZUH_REQUEST_TIMEOUT", "10"))
    except ValueError:
        wazuh["request_timeout_seconds"] = 10

    splunk = data.setdefault("splunk_api", {})
    splunk["url"] = os.getenv("SPLUNK_URL", "https://localhost:8089")
    splunk["token"] = os.getenv("SPLUNK_TOKEN", "")
    splunk["index"] = os.getenv("SPLUNK_INDEX", "main")
    splunk["sourcetype"] = os.getenv("SPLUNK_SOURCETYPE", "WinEventLog:Security")
    splunk["verify_ssl"] = os.getenv("SPLUNK_VERIFY_SSL", "true").lower() != "false"
    try:
        splunk["request_timeout_seconds"] = int(os.getenv("SPLUNK_REQUEST_TIMEOUT", "30"))
        splunk["max_events"] = min(1000, max(1, int(os.getenv("SPLUNK_MAX_EVENTS", "500"))))
    except ValueError:
        splunk["request_timeout_seconds"], splunk["max_events"] = 30, 500

    # simulation_mode can never be force-disabled via env accidentally without an explicit flag
    if os.getenv("ITRAP_DISABLE_SIMULATION", "false").lower() == "true":
        data.setdefault("response_policy", {})["simulation_mode"] = False

    return data


_config_instance: AppConfig | None = None


def load_config(force_reload: bool = False) -> AppConfig:
    """Loads and validates the merged application configuration (singleton)."""
    global _config_instance
    if _config_instance is not None and not force_reload:
        return _config_instance

    raw = _load_yaml(CONFIG_DIR / "config.yaml")

    risk_weights = _load_yaml(CONFIG_DIR / "risk_weights.yaml")
    raw["_risk_weights"] = risk_weights

    response_policy = _load_yaml(CONFIG_DIR / "response_policy.yaml")
    if response_policy:
        raw["response_policy"] = {**raw.get("response_policy", {}), **response_policy}

    ti_section = raw.get("threat_intelligence", {})
    ai_section = raw.get("ai", {})
    raw["threat_intelligence"] = ti_section
    raw["ai"] = ai_section

    raw = _apply_env_overrides(raw)

    risk_weights_data = raw.pop("_risk_weights", {})

    try:
        cfg = AppConfig(**raw)
    except Exception as exc:  # noqa: BLE001
        raise ConfigurationError(f"Failed to load configuration: {exc}") from exc

    cfg.__dict__["_risk_weights"] = risk_weights_data
    _config_instance = cfg
    return cfg


def get_risk_weights() -> dict[str, Any]:
    cfg = load_config()
    weights = cfg.__dict__.get("_risk_weights", {})
    if not weights:
        weights = _load_yaml(CONFIG_DIR / "risk_weights.yaml")
    return weights


def get_detection_rules_config() -> dict[str, Any]:
    return _load_yaml(CONFIG_DIR / "detection_rules.yaml")


def get_mitre_mapping_config() -> dict[str, Any]:
    return _load_yaml(CONFIG_DIR / "mitre_mapping.yaml")
