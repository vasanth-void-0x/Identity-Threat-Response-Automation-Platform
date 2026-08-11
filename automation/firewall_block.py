"""
automation/firewall_block.py
Simulated (default) / optional real IP block action. Real mode invokes a
local Windows Firewall rule via netsh through scripts/simulate_attack.ps1's
sibling response scripts - never invoked directly here unless real_mode=True
and policy checks pass. Private IPs, localhost, and protected networks can
never be blocked regardless of mode.
"""

from __future__ import annotations

import ipaddress
import subprocess

from core.config import load_config
from core.exceptions import ResponseActionError
from core.logger import get_logger
from core.validators import is_private_ip, is_reserved_demo_ip
from automation.simulation import simulated_result

logger = get_logger(__name__)


def _is_protected(ip: str) -> bool:
    cfg = load_config().response_policy
    if not cfg.allow_private_ip_blocking and is_private_ip(ip) and not is_reserved_demo_ip(ip):
        return True
    if not cfg.allow_localhost_blocking and ip in ("127.0.0.1", "::1"):
        return True
    for network in cfg.protected_networks:
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
                return True
        except ValueError:
            continue
    return False


def block_ip(ip: str, real_mode: bool = False) -> str:
    if _is_protected(ip):
        raise ResponseActionError(f"Refusing to block protected/private IP: {ip}")

    if not real_mode:
        return simulated_result("block_ip", ip)

    cfg = load_config().response_policy
    if cfg.simulation_mode:
        raise ResponseActionError("Real actions are disabled - response_policy.simulation_mode is True")

    try:
        rule_name = f"ITRAP_Block_{ip.replace('.', '_')}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
            check=True, capture_output=True, timeout=10,
        )
        return f"[REAL] Windows Firewall rule '{rule_name}' created, blocking inbound traffic from {ip}"
    except Exception as exc:  # noqa: BLE001
        logger.error("Real firewall block failed for %s: %s", ip, exc)
        raise ResponseActionError(f"Failed to block IP {ip}: {exc}") from exc
