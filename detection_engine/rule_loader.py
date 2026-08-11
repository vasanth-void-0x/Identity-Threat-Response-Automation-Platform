"""detection_engine/rule_loader.py - Instantiates all detection rules with their YAML config."""

from __future__ import annotations

from core.config import get_detection_rules_config
from detection_engine.base_rule import BaseDetectionRule
from detection_engine.rules.account_creation import AccountCreationRule
from detection_engine.rules.account_lockout import AccountLockoutRule
from detection_engine.rules.brute_force import BruteForceRule
from detection_engine.rules.group_membership_change import GroupMembershipChangeRule
from detection_engine.rules.impossible_travel import ImpossibleTravelRule
from detection_engine.rules.new_device import NewDeviceRule
from detection_engine.rules.new_source_ip import NewSourceIPRule
from detection_engine.rules.privileged_logon import PrivilegedLogonRule
from detection_engine.rules.successful_login_after_failures import SuccessfulLoginAfterFailuresRule
from detection_engine.rules.suspicious_powershell import SuspiciousPowerShellRule
from detection_engine.rules.suspicious_process import SuspiciousProcessRule

RULE_REGISTRY: dict[str, type[BaseDetectionRule]] = {
    "brute_force": BruteForceRule,
    "successful_login_after_failures": SuccessfulLoginAfterFailuresRule,
    "new_source_ip": NewSourceIPRule,
    "new_device": NewDeviceRule,
    "impossible_travel": ImpossibleTravelRule,
    "privileged_logon": PrivilegedLogonRule,
    "suspicious_powershell": SuspiciousPowerShellRule,
    "account_lockout": AccountLockoutRule,
    "account_creation": AccountCreationRule,
    "group_membership_change": GroupMembershipChangeRule,
    "suspicious_process": SuspiciousProcessRule,
}


def load_enabled_rules() -> list[BaseDetectionRule]:
    """Reads configs/detection_rules.yaml and returns instantiated, enabled rules."""
    rules_config = get_detection_rules_config().get("rules", {})
    enabled_rules: list[BaseDetectionRule] = []

    for rule_key, rule_cls in RULE_REGISTRY.items():
        rule_cfg = rules_config.get(rule_key, {})
        if rule_cfg.get("enabled", True):
            enabled_rules.append(rule_cls(config=rule_cfg))

    return enabled_rules
