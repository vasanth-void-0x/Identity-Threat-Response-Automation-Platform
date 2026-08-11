"""tests/test_automation.py - Tests for the response engine (simulation mode only, no network)."""

from automation.response_engine import execute_action
from automation.simulation import simulated_result
from database import repository
from models.incident import Incident


def test_execute_action_simulation_mode():
    incident = Incident(title="Test", severity="high", risk_score=70)
    repository.save_incidents([incident])

    action = execute_action(
        incident_id=incident.incident_id,
        action_type="block_ip",
        target="198.51.100.66",
        severity="high",
        requested_by="analyst1",
        real_mode=False,
    )
    assert action.mode == "simulation"
    assert action.status == "executed"
    assert "[SIMULATION]" in action.result


def test_execute_action_rejects_disallowed_action():
    incident = Incident(title="Test", severity="high", risk_score=70)
    repository.save_incidents([incident])

    action = execute_action(
        incident_id=incident.incident_id,
        action_type="not_a_real_action",
        target="x",
        severity="high",
        requested_by="analyst1",
    )
    assert action.status == "failed"
    assert action.error is not None


def test_execute_action_persists_to_db():
    incident = Incident(title="Test", severity="critical", risk_score=90)
    repository.save_incidents([incident])

    execute_action(
        incident_id=incident.incident_id,
        action_type="create_ticket",
        target=incident.incident_id,
        severity="critical",
        requested_by="analyst1",
    )
    actions = repository.get_response_actions(incident_id=incident.incident_id)
    assert len(actions) == 1
    assert actions[0]["action_type"] == "create_ticket"


def test_disable_account_protects_administrator():
    from automation.disable_account import disable_account
    from core.exceptions import ResponseActionError
    import pytest
    with pytest.raises(ResponseActionError):
        disable_account("Administrator", real_mode=True)


def test_block_ip_protects_private_ip():
    from automation.firewall_block import block_ip
    from core.exceptions import ResponseActionError
    import pytest
    with pytest.raises(ResponseActionError):
        block_ip("192.168.1.10", real_mode=True)


def test_simulated_result_format():
    result = simulated_result("block_ip", "198.51.100.66")
    assert "[SIMULATION]" in result
    assert "198.51.100.66" in result
