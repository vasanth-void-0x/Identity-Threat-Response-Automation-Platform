"""
tests/test_approval_workflow.py
Tests for the real-response-action approval workflow: request -> approve/
reject -> execute, self-approval blocking, protected targets, and
simulation-mode safety. All system-changing functions are mocked - no real
commands are ever executed by these tests.
"""

from unittest.mock import patch

import pytest

from automation.response_engine import approve_action, execute_action, reject_action, request_real_action
from core.config import load_config
from core.exceptions import ResponseActionError
from database import repository
from models.incident import Incident


def _seed_incident(severity="critical"):
    incident = Incident(title="Test incident", severity=severity, risk_score=90)
    repository.save_incidents([incident])
    return incident


def test_simulation_action_executes_immediately_no_approval_needed():
    incident = _seed_incident()
    action = execute_action(
        incident_id=incident.incident_id, action_type="block_ip", target="198.51.100.66",
        severity=incident.severity, requested_by="analyst1", real_mode=False,
    )
    assert action.mode == "simulation"
    assert action.status == "executed"
    assert action.approved_by is None


def test_real_action_blocked_when_simulation_mode_enabled():
    """simulation_mode defaults to True - real action requests must be rejected."""
    incident = _seed_incident()
    action = request_real_action(
        incident_id=incident.incident_id, action_type="block_ip", target="198.51.100.66",
        severity=incident.severity, requested_by="analyst1",
    )
    assert action.status == "failed"
    assert "simulation_mode" in action.error.lower() or "disabled" in action.error.lower()


def test_real_action_creates_pending_approval_when_simulation_disabled(monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(cfg.response_policy, "simulation_mode", False)

    incident = _seed_incident(severity="critical")
    action = request_real_action(
        incident_id=incident.incident_id, action_type="block_ip", target="198.51.100.66",
        severity=incident.severity, requested_by="analyst1",
    )
    assert action.status == "pending_approval"
    assert action.mode == "real"


def test_real_action_blocked_below_minimum_severity(monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(cfg.response_policy, "simulation_mode", False)

    incident = _seed_incident(severity="low")
    action = request_real_action(
        incident_id=incident.incident_id, action_type="block_ip", target="198.51.100.66",
        severity=incident.severity, requested_by="analyst1",
    )
    assert action.status == "failed"
    assert "severity" in action.error.lower()


def test_real_action_blocked_for_protected_user(monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(cfg.response_policy, "simulation_mode", False)

    incident = _seed_incident(severity="critical")
    action = request_real_action(
        incident_id=incident.incident_id, action_type="disable_account", target="administrator",
        severity=incident.severity, requested_by="analyst1",
    )
    assert action.status == "failed"
    assert "protected" in action.error.lower()


def test_self_approval_is_blocked(monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(cfg.response_policy, "simulation_mode", False)

    incident = _seed_incident(severity="critical")
    action = request_real_action(
        incident_id=incident.incident_id, action_type="block_ip", target="198.51.100.66",
        severity=incident.severity, requested_by="analyst1",
    )
    assert action.status == "pending_approval"

    with pytest.raises(ResponseActionError, match="Self-approval"):
        approve_action(action.action_id, "analyst1")

    # Confirm the action was NOT executed / status unchanged
    record = repository.get_response_action(action.action_id)
    assert record["status"] == "pending_approval"


def test_different_analyst_can_approve_and_action_executes(monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(cfg.response_policy, "simulation_mode", False)

    incident = _seed_incident(severity="critical")
    action = request_real_action(
        incident_id=incident.incident_id, action_type="block_ip", target="198.51.100.66",
        severity=incident.severity, requested_by="analyst1",
    )

    with patch("automation.firewall_block.subprocess.run") as mock_run:
        mock_run.return_value = None
        result = approve_action(action.action_id, "analyst2")

    assert result.status == "executed"
    assert result.approved_by == "analyst2"
    assert result.approved_at is not None
    assert result.mode == "real"
    mock_run.assert_called_once()  # confirms the (mocked) real command was invoked exactly once


def test_reject_action_never_executes(monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(cfg.response_policy, "simulation_mode", False)

    incident = _seed_incident(severity="critical")
    action = request_real_action(
        incident_id=incident.incident_id, action_type="disable_account", target="bob",
        severity=incident.severity, requested_by="analyst1",
    )

    with patch("automation.disable_account.subprocess.run") as mock_run:
        result = reject_action(action.action_id, "analyst2", reason="Not warranted")
        mock_run.assert_not_called()

    assert result.status == "rejected"
    assert result.rejected_by == "analyst2"
    assert result.rejection_reason == "Not warranted"


def test_cannot_approve_already_executed_action(monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(cfg.response_policy, "simulation_mode", False)

    incident = _seed_incident(severity="critical")
    action = request_real_action(
        incident_id=incident.incident_id, action_type="block_ip", target="198.51.100.66",
        severity=incident.severity, requested_by="analyst1",
    )
    with patch("automation.firewall_block.subprocess.run"):
        approve_action(action.action_id, "analyst2")

    with pytest.raises(ResponseActionError, match="not pending approval"):
        approve_action(action.action_id, "analyst3")


def test_action_history_shows_full_approval_trail(monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(cfg.response_policy, "simulation_mode", False)

    incident = _seed_incident(severity="critical")
    action = request_real_action(
        incident_id=incident.incident_id, action_type="block_ip", target="198.51.100.66",
        severity=incident.severity, requested_by="analyst1",
    )
    with patch("automation.firewall_block.subprocess.run"):
        approve_action(action.action_id, "analyst2")

    record = repository.get_response_action(action.action_id)
    assert record["requested_by"] == "analyst1"
    assert record["approved_by"] == "analyst2"
    assert record["approved_at"] is not None
    assert record["executed_at"] is not None
    assert record["mode"] == "real"
