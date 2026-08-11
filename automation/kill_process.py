"""
automation/kill_process.py
Simulated (default) / optional real process-termination action. Termination
is not reversible, so this action always requires real_mode=True plus
explicit analyst approval when simulation_mode is disabled.
"""

from __future__ import annotations

import subprocess

from core.config import load_config
from core.exceptions import ResponseActionError
from core.logger import get_logger
from automation.simulation import simulated_result

logger = get_logger(__name__)

_PROTECTED_PROCESS_NAMES = {"system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"}


def kill_process(process_id: str, process_name: str = "", real_mode: bool = False) -> str:
    if process_name.lower() in _PROTECTED_PROCESS_NAMES:
        raise ResponseActionError(f"Refusing to kill protected system process: {process_name}")

    target_label = f"{process_name} (PID {process_id})" if process_name else f"PID {process_id}"

    if not real_mode:
        return simulated_result("kill_process", target_label)

    cfg = load_config().response_policy
    if cfg.simulation_mode:
        raise ResponseActionError("Real actions are disabled - response_policy.simulation_mode is True")
    # NOTE: analyst-approval enforcement happens upstream in
    # automation.response_engine (request_real_action -> approve_action,
    # with self-approval blocked) before this function is ever called with
    # real_mode=True - see disable_account.py for the same note.

    try:
        subprocess.run(["taskkill", "/PID", str(process_id), "/F"], check=True, capture_output=True, timeout=10)
        return f"[REAL] Process {target_label} terminated"
    except Exception as exc:  # noqa: BLE001
        logger.error("Real process kill failed for %s: %s", target_label, exc)
        raise ResponseActionError(f"Failed to kill process {target_label}: {exc}") from exc
