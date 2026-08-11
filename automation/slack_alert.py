"""
automation/slack_alert.py
Optional Slack webhook notification for high/critical incidents. Disabled by
default (slack_enabled: false). Webhook URL is read from environment/config
and never hardcoded or logged in plaintext.
"""

from __future__ import annotations

import requests

from core.config import load_config
from core.logger import get_logger
from automation.simulation import simulated_result

logger = get_logger(__name__)


def send_slack_alert(message: str) -> str:
    cfg = load_config()

    if not cfg.slack_enabled or not cfg.slack_webhook_url:
        return simulated_result("slack_alert", "#soc-alerts (no webhook configured)")

    try:
        resp = requests.post(cfg.slack_webhook_url, json={"text": message}, timeout=5)
        resp.raise_for_status()
        return "[REAL] Slack alert posted successfully"
    except Exception as exc:  # noqa: BLE001
        logger.warning("Slack alert failed, falling back to simulation record: %s", exc)
        return simulated_result("slack_alert", "#soc-alerts")
