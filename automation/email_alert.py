"""
automation/email_alert.py
Optional email notification for high/critical incidents. Disabled by default
(email_enabled: false in config.yaml). Uses SMTP settings from config/env -
never hardcodes credentials. Falls back to simulation when disabled or
misconfigured.
"""

from __future__ import annotations

import smtplib
from email.mime.text import MIMEText

from core.config import load_config
from core.logger import get_logger
from automation.simulation import simulated_result

logger = get_logger(__name__)


def send_email_alert(subject: str, body: str) -> str:
    cfg = load_config()

    if not cfg.email_enabled or not cfg.email_smtp_host or not cfg.email_to:
        return simulated_result("email_alert", cfg.email_to or "(no recipient configured)")

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = cfg.email_from
        msg["To"] = cfg.email_to

        with smtplib.SMTP(cfg.email_smtp_host, cfg.email_smtp_port, timeout=10) as server:
            server.starttls()
            server.send_message(msg)

        return f"[REAL] Email alert sent to {cfg.email_to}"
    except Exception as exc:  # noqa: BLE001
        logger.warning("Email alert failed, falling back to simulation record: %s", exc)
        return simulated_result("email_alert", cfg.email_to)
