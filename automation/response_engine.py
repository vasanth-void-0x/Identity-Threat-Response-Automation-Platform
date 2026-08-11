"""
automation/response_engine.py
Policy-based response engine with a full approval workflow for real
(non-simulated) actions.

Two entry points:
  - execute_action(...)      Simulation-path actions (dashboard default) -
                              always simulated, executes immediately, no
                              approval gate needed since nothing real happens.
  - request_real_action(...) Real-mode actions - creates a pending_approval
                              record after policy validation. Nothing is
                              executed until a second, different analyst
                              calls approve_action().

Approval workflow states: pending_approval -> approved -> executed
                           pending_approval -> rejected
                           any -> failed (policy violation / execution error)

Every state transition is persisted and audit-logged, whether the action is
simulated, real, approved, rejected, or blocked by policy.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.config import load_config
from core.constants import SEVERITY_ORDER
from core.exceptions import ResponseActionError
from core.logger import get_logger
from automation import (
    disable_account as disable_account_module,
    email_alert,
    firewall_block,
    isolate_host as isolate_host_module,
    kill_process as kill_process_module,
    slack_alert,
    ticket_creator,
)
from automation.audit_logger import record_action_audit
from automation.simulation import build_rollback_info
from database import repository
from models.response_action import ResponseAction

logger = get_logger(__name__)

_DISPATCH = {
    "block_ip": lambda target, real_mode: firewall_block.block_ip(target, real_mode=real_mode),
    "disable_account": lambda target, real_mode: disable_account_module.disable_account(target, real_mode=real_mode),
    "isolate_host": lambda target, real_mode: isolate_host_module.isolate_host(target, real_mode=real_mode),
    "kill_process": lambda target, real_mode: kill_process_module.kill_process(target, real_mode=real_mode),
    "create_ticket": lambda target, real_mode: ticket_creator.create_ticket(target, "", ""),
    "email_alert": lambda target, real_mode: email_alert.send_email_alert(f"ITRAP Alert: {target}", target),
    "slack_alert": lambda target, real_mode: slack_alert.send_slack_alert(target),
    "flag_for_review": lambda target, real_mode: f"[SIMULATION] Incident {target} flagged for analyst review.",
}


def _meets_severity_threshold(severity: str, minimum: str) -> bool:
    try:
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(minimum)
    except ValueError:
        return False


def _validate_policy(action_type: str, target: str, severity: str, cfg) -> None:
    """Raises ResponseActionError if the action fails any policy gate. Shared by both entry points."""
    if action_type not in cfg.action_allowlist:
        raise ResponseActionError(f"Action '{action_type}' is not in the response policy allowlist")

    if not _meets_severity_threshold(severity, cfg.minimum_severity_threshold):
        raise ResponseActionError(
            f"Incident severity '{severity}' is below the minimum threshold "
            f"'{cfg.minimum_severity_threshold}' required for real response actions"
        )

    if action_type not in _DISPATCH:
        raise ResponseActionError(f"Unknown action type: {action_type}")


def execute_action(
    incident_id: str,
    action_type: str,
    target: str,
    severity: str,
    requested_by: str = "analyst",
    real_mode: bool = False,
) -> ResponseAction:
    """
    Simulation-path entry point (used by the dashboard's "Execute Action"
    button, which never passes real_mode=True). Executes immediately since
    simulation actions make no real system change and therefore need no
    approval gate. If real_mode=True AND simulation is globally disabled,
    this delegates to the approval-gated path instead of executing directly.
    """
    cfg = load_config().response_policy

    effective_real_mode = real_mode and not cfg.simulation_mode
    if effective_real_mode:
        # Real execution must always go through the approval workflow - never
        # execute directly from this entry point, regardless of caller intent.
        return request_real_action(incident_id, action_type, target, severity, requested_by)

    action = ResponseAction(
        incident_id=incident_id,
        action_type=action_type,
        target=target,
        requested_by=requested_by,
        mode="simulation",
        status="pending_approval",
    )

    try:
        _validate_policy(action_type, target, severity, cfg)
        handler = _DISPATCH[action_type]
        result = handler(target, False)
        action.result = result
        action.status = "executed"
        action.executed_at = datetime.now(timezone.utc)
        action.rollback_info = {}
    except ResponseActionError as exc:
        action.status = "failed"
        action.error = str(exc)
        action.result = f"Action blocked by policy: {exc}"
        logger.warning("Simulated response action blocked: %s", exc)

    repository.save_response_action(action)
    record_action_audit(requested_by, action_type, target, incident_id, action.result)
    return action


def request_real_action(
    incident_id: str,
    action_type: str,
    target: str,
    severity: str,
    requested_by: str = "analyst",
) -> ResponseAction:
    """
    Requests a REAL (non-simulated) response action. Validates policy
    (allowlist, severity threshold, protected target) up front and fails
    fast if any gate is not met. If validation passes, creates a
    pending_approval record - nothing is executed here. A different,
    identified analyst must call approve_action() before anything real
    happens.
    """
    cfg = load_config().response_policy

    action = ResponseAction(
        incident_id=incident_id,
        action_type=action_type,
        target=target,
        requested_by=requested_by,
        mode="real",
        status="pending_approval",
    )

    try:
        if cfg.simulation_mode:
            raise ResponseActionError(
                "Real actions are disabled - response_policy.simulation_mode is True. "
                "Set ITRAP_DISABLE_SIMULATION=true to allow real actions in an isolated lab."
            )
        _validate_policy(action_type, target, severity, cfg)
        _check_target_not_protected(action_type, target, cfg)
        # Policy passed - leave status as pending_approval, awaiting a second analyst.
        action.result = "Awaiting analyst approval before real execution."
    except ResponseActionError as exc:
        action.status = "failed"
        action.error = str(exc)
        action.result = f"Real action request blocked by policy: {exc}"
        logger.warning("Real response action request blocked: %s", exc)

    repository.save_response_action(action)
    record_action_audit(requested_by, f"request_real:{action_type}", target, incident_id, action.result)
    return action


def _check_target_not_protected(action_type: str, target: str, cfg) -> None:
    """Delegates to the relevant automation module's own protection checks via a dry probe."""
    if action_type == "block_ip":
        from core.validators import is_private_ip, is_reserved_demo_ip
        import ipaddress
        if not cfg.allow_private_ip_blocking and is_private_ip(target) and not is_reserved_demo_ip(target):
            raise ResponseActionError(f"Refusing to request block of protected/private IP: {target}")
        for network in cfg.protected_networks:
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(network):
                    raise ResponseActionError(f"Refusing to request block of protected network member: {target}")
            except ValueError:
                continue
    elif action_type == "disable_account":
        always_protected = {"administrator", "system", "local service", "network service"}
        lowered = target.lower()
        if lowered in always_protected or lowered in {u.lower() for u in cfg.protected_users}:
            raise ResponseActionError(f"Refusing to request disable of protected account: {target}")
    elif action_type == "isolate_host":
        if target.lower() in {h.lower() for h in cfg.protected_hosts}:
            raise ResponseActionError(f"Refusing to request isolation of protected host: {target}")


def approve_action(action_id: str, approver: str) -> ResponseAction:
    """
    Approves a pending_approval real action and immediately executes it.
    The approver must be a different, identified analyst than the original
    requester - self-approval is never permitted, regardless of policy
    settings, so a single compromised or careless analyst account cannot
    both request and approve a real, potentially destructive action.
    """
    record = repository.get_response_action(action_id)
    if not record:
        raise ResponseActionError(f"Response action {action_id} not found")

    if record["status"] != "pending_approval":
        raise ResponseActionError(
            f"Action {action_id} is '{record['status']}', not pending approval - cannot approve"
        )

    if not approver or approver.strip().lower() == (record.get("requested_by") or "").strip().lower():
        raise ResponseActionError(
            "Self-approval is not permitted - the approving analyst must be different from the requester"
        )

    cfg = load_config().response_policy
    now = datetime.now(timezone.utc)

    # Revalidate every safety decision at approval time. A pending request must
    # never turn into a simulated action labelled as a real execution.
    if cfg.simulation_mode:
        raise ResponseActionError("Real execution is disabled because simulation mode is enabled")
    requested_at = datetime.fromisoformat(str(record["timestamp"]).replace("Z", "+00:00"))
    if now - requested_at > timedelta(minutes=30):
        repository.update_response_action_status(
            action_id, status="failed", error="Approval request expired",
            result="Real action request expired after 30 minutes",
        )
        raise ResponseActionError("Approval request expired after 30 minutes")
    incident = repository.get_incident(record["incident_id"])
    if not incident:
        raise ResponseActionError("Related incident no longer exists")
    if incident.get("status") in {"resolved", "false_positive"}:
        raise ResponseActionError(f"Incident is {incident['status']}; real action is no longer allowed")
    _validate_policy(record["action_type"], record["target"], incident["severity"], cfg)
    _check_target_not_protected(record["action_type"], record["target"], cfg)

    approved_fields = {"status": "approved", "approved_by": approver, "approved_at": now.isoformat()}
    repository.update_response_action_status(action_id, **approved_fields)
    record_action_audit(approver, f"approve:{record['action_type']}", record["target"], record["incident_id"],
                         f"Approved by {approver}")

    # Immediately execute now that approval has been granted.
    action_type = record["action_type"]
    target = record["target"]
    incident_id = record["incident_id"]

    try:
        effective_real_mode = True
        handler = _DISPATCH[action_type]
        result = handler(target, effective_real_mode)
        final_fields = {
            "status": "executed",
            "result": result,
            "executed_at": now.isoformat(),
        }
        if effective_real_mode:
            import json
            final_fields["rollback_info"] = json.dumps(build_rollback_info(action_type, target))
    except Exception as exc:  # noqa: BLE001
        final_fields = {"status": "failed", "error": str(exc), "result": f"Execution failed: {exc}"}
        logger.error("Approved real action %s failed during execution: %s", action_id, exc)

    repository.update_response_action_status(action_id, **final_fields)
    record_action_audit(approver, f"execute:{action_type}", target, incident_id, final_fields.get("result", ""))

    updated = repository.get_response_action(action_id)
    return ResponseAction(**{k: v for k, v in updated.items() if k in ResponseAction.model_fields})


def reject_action(action_id: str, rejector: str, reason: str = "") -> ResponseAction:
    """Rejects a pending_approval action. No system change ever occurs for a rejected action."""
    record = repository.get_response_action(action_id)
    if not record:
        raise ResponseActionError(f"Response action {action_id} not found")

    if record["status"] != "pending_approval":
        raise ResponseActionError(
            f"Action {action_id} is '{record['status']}', not pending approval - cannot reject"
        )

    now = datetime.now(timezone.utc)
    fields = {
        "status": "rejected",
        "rejected_by": rejector,
        "rejected_at": now.isoformat(),
        "rejection_reason": reason or "No reason provided",
        "result": f"Rejected by {rejector}: {reason or 'No reason provided'}",
    }
    repository.update_response_action_status(action_id, **fields)
    record_action_audit(rejector, f"reject:{record['action_type']}", record["target"], record["incident_id"],
                         fields["result"])

    updated = repository.get_response_action(action_id)
    return ResponseAction(**{k: v for k, v in updated.items() if k in ResponseAction.model_fields})
