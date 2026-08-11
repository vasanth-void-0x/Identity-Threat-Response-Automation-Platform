"""
core/logger.py
Central logging configuration. Never logs secrets (API keys, passwords, tokens).
Provides a dedicated audit logger for analyst / response actions.
"""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_SECRET_PATTERN = re.compile(
    r"(api[_-]?key|token|password|secret|webhook_url)\s*[:=]\s*\S+", re.IGNORECASE
)


class SecretRedactingFilter(logging.Filter):
    """Redacts anything that looks like a secret before it hits a log sink."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _SECRET_PATTERN.sub(r"\1=***REDACTED***", record.msg)
        return True


_initialized = False


def setup_logging(log_level: str = "INFO", log_dir: str = "logs") -> None:
    global _initialized
    if _initialized:
        return

    log_path = PROJECT_ROOT / log_dir
    log_path.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(log_level)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.addFilter(SecretRedactingFilter())
    root.addHandler(console)

    file_handler = RotatingFileHandler(
        log_path / "app.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SecretRedactingFilter())
    root.addHandler(file_handler)

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def get_audit_logger() -> logging.Logger:
    """Dedicated audit trail logger - incident status changes, approvals, response actions."""
    log_path = PROJECT_ROOT / "logs"
    log_path.mkdir(parents=True, exist_ok=True)

    audit_logger = logging.getLogger("audit")
    if not audit_logger.handlers:
        audit_logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            log_path / "audit.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        handler.addFilter(SecretRedactingFilter())
        audit_logger.addHandler(handler)
        audit_logger.propagate = False
    return audit_logger
