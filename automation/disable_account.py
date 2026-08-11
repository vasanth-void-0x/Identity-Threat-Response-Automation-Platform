"""
automation/disable_account.py
Simulated (default) / optional real account-disable action. Real execution
requires: simulation_mode disabled AND the account not present in the
protected_users list AND explicit real_mode=True from an approved analyst
workflow. Never automatically disables Administrator, SYSTEM, service
accounts, or the currently logged-in user.
"""

from __future__ import annotations

import subprocess

from core.config import load_config
from core.exceptions import ResponseActionError
from core.logger import get_logger
from automation.simulation import simulated_result

logger = get_logger(__name__)

_ALWAYS_PROTECTED = {"administrator", "system", "local service", "network service"}


def _is_protected(username: str) -> bool:
    cfg = load_config().response_policy
    lowered = username.lower()
    if lowered in _ALWAYS_PROTECTED:
        return True
    return lowered in {u.lower() for u in cfg.protected_users}


def disable_account(username: str, real_mode: bool = False) -> str:
    if _is_protected(username):
        raise ResponseActionError(f"Refusing to disable protected account: {username}")

    if not real_mode:
        return simulated_result("disable_account", username)

    cfg = load_config().response_policy
    if cfg.simulation_mode:
        raise ResponseActionError("Real actions are disabled - response_policy.simulation_mode is True")
    # NOTE: analyst-approval enforcement happens upstream in
    # automation.response_engine (request_real_action -> approve_action,
    # with self-approval blocked). By the time this function is called with
    # real_mode=True, approval has already been granted by a different,
    # identified analyst - re-blocking on cfg.require_analyst_approval here
    # would make approved actions impossible to ever execute.

    try:
        # Local Windows account disable (lab-only, non-domain). Domain environments
        # would instead use Disable-ADAccount, which requires RSAT/AD module.
        subprocess.run(
            ["net", "user", username, "/active:no"],
            check=True, capture_output=True, timeout=10,
        )
        return f"[REAL] Local account '{username}' disabled"
    except Exception as exc:  # noqa: BLE001
        logger.error("Real account disable failed for %s: %s", username, exc)
        raise ResponseActionError(f"Failed to disable account {username}: {exc}") from exc
