"""automation/audit_logger.py - Thin wrapper recording every response action to the audit trail."""

from __future__ import annotations

from database.repository import log_audit


def record_action_audit(actor: str, action_type: str, target: str, incident_id: str, result: str) -> None:
    log_audit(
        actor=actor,
        action=f"response_action:{action_type}",
        target=target,
        details={"incident_id": incident_id, "result": result},
    )
