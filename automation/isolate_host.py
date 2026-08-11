"""
automation/isolate_host.py
Simulated (default) / optional real host-isolation action. Real mode would
apply a restrictive Windows Firewall profile blocking all traffic except to
the management subnet - disabled by default and gated behind the same
policy checks as every other real response action.
"""

from __future__ import annotations

from core.config import load_config
from core.exceptions import ResponseActionError
from automation.simulation import simulated_result


def isolate_host(hostname: str, real_mode: bool = False) -> str:
    cfg = load_config().response_policy
    if hostname.lower() in {h.lower() for h in cfg.protected_hosts}:
        raise ResponseActionError(f"Refusing to isolate protected host: {hostname}")

    if not real_mode:
        return simulated_result("isolate_host", hostname)

    if cfg.simulation_mode:
        raise ResponseActionError("Real actions are disabled - response_policy.simulation_mode is True")

    # Intentionally not implemented for real execution in this lab project -
    # host isolation requires an EDR/network-control integration out of scope
    # for a local demo. Raise clearly rather than silently no-op.
    raise ResponseActionError(
        "Real host isolation requires an EDR or network-control integration not present in this lab build. "
        "Use simulation mode."
    )
