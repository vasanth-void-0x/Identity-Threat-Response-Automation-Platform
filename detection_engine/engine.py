"""
detection_engine/engine.py
Top-level orchestrator: runs all enabled detection rules against a batch of
normalized events, scores each resulting alert, enriches with threat intel,
and correlates alerts into incidents.

Baseline context (known IPs/devices per user) is loaded from persisted trusted
tables before rule evaluation. Observed values are never saved automatically;
only an explicit, audited analyst action may change the trusted baseline.
"""

from __future__ import annotations

from core.logger import get_logger
from database import repository
from detection_engine.correlation import correlate_alerts
from detection_engine.risk_scoring import score_alert
from detection_engine.rule_loader import load_enabled_rules
from models.alert import Alert
from models.event import NormalizedEvent
from models.incident import Incident
from threat_intelligence.manager import ThreatIntelManager

logger = get_logger(__name__)


class DetectionEngine:
    def __init__(self, threat_intel: ThreatIntelManager | None = None):
        self.rules = load_enabled_rules()
        self.threat_intel = threat_intel or ThreatIntelManager()
        logger.info("Detection engine initialized with %d enabled rules", len(self.rules))

    def run(self, events: list[NormalizedEvent], persist_baseline: bool = False) -> tuple[list[Alert], list[Incident]]:
        events = sorted(events, key=lambda e: e.timestamp)

        context: dict = {
            "known_ips": repository.load_known_ips(),
            "known_devices": repository.load_known_devices(),
        }
        all_alerts: list[Alert] = []

        for rule in self.rules:
            try:
                alerts = rule.evaluate(events, context)
                all_alerts.extend(alerts)
                if alerts:
                    logger.info("Rule '%s' fired %d alert(s)", rule.rule_name, len(alerts))
            except Exception as exc:  # noqa: BLE001
                logger.error("Rule '%s' failed: %s", rule.rule_name, exc)

        for alert in all_alerts:
            malicious = False
            if alert.source_ip:
                enrichment = self.threat_intel.lookup_ip(alert.source_ip)
                malicious = enrichment.get("reputation") == "malicious"
                alert.metadata["threat_intel"] = enrichment
            score_alert(alert, threat_intel_malicious=malicious)

        incidents = correlate_alerts(all_alerts)
        logger.info("Generated %d alert(s) -> %d incident(s)", len(all_alerts), len(incidents))

        # Detection must never promote observed values into the trusted baseline.
        # Baselines are changed only by explicit analyst actions in repository.py.
        # ``persist_baseline`` remains in the signature for backward compatibility.

        return all_alerts, incidents
