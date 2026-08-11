"""
ai_engine/incident_summary.py
Generates an AI (or deterministic mock) summary for an incident. This is the
single function the dashboard / database layer calls - it handles provider
selection and fallback internally.
"""

from __future__ import annotations

from ai_engine.groq_provider import GroqProvider
from ai_engine.mock_provider import MockAIProvider
from ai_engine.prompts import build_incident_prompt
from core.config import load_config
from core.logger import get_logger
from models.incident import Incident

logger = get_logger(__name__)


def _incident_to_context(incident: Incident, alert_titles: list[str]) -> dict:
    return {
        "title": incident.title,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "user": incident.user,
        "source_ips": incident.source_ips,
        "hosts": incident.hosts,
        "mitre_techniques": incident.mitre_techniques,
        "alert_titles": alert_titles,
    }


def generate_incident_summary(incident: Incident, alert_titles: list[str]) -> str:
    cfg = load_config().ai
    context = _incident_to_context(incident, alert_titles)

    if cfg.provider == "groq" and cfg.groq_api_key:
        try:
            provider = GroqProvider(cfg.groq_api_key, cfg.model)
            prompt = build_incident_prompt(context)
            return provider.generate_incident_analysis(prompt)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Groq AI summary failed, falling back to mock provider: %s", exc)

    return MockAIProvider().generate_from_context(context)
