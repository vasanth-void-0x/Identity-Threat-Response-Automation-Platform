"""
automation/simulation.py
Core simulation helpers shared by every response action module. In simulation
mode (the default), actions are logged and recorded but no real system change
occurs. Real execution is only possible when explicitly enabled per-action
via response_policy.yaml AND the action passes all policy safety checks.
"""

from __future__ import annotations

from datetime import datetime, timezone


def simulated_result(action_type: str, target: str) -> str:
    return (
        f"[SIMULATION] {action_type} against '{target}' was recorded but NOT executed. "
        f"No real system, account, or network change was made. Timestamp: "
        f"{datetime.now(timezone.utc).isoformat()}"
    )


def build_rollback_info(action_type: str, target: str) -> dict:
    """Describes how a real (non-simulated) action of this type would be rolled back."""
    rollback_map = {
        "block_ip": f"Remove firewall rule blocking {target}",
        "disable_account": f"Re-enable account {target} in Active Directory / local system",
        "isolate_host": f"Restore network connectivity for host {target}",
        "kill_process": "Not reversible - process termination has no rollback",
    }
    return {"instructions": rollback_map.get(action_type, "No rollback procedure defined")}
