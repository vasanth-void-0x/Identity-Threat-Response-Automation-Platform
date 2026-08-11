"""
ai_engine/mock_provider.py
Deterministic, offline AI provider. Default provider when no GROQ_API_KEY is
configured. Produces a structured, rule-based "analyst aid" summary from
incident data rather than a real LLM call.
"""

from __future__ import annotations

from ai_engine.provider import AIProvider


class MockAIProvider(AIProvider):
    def generate_incident_analysis(self, prompt: str) -> str:
        # The mock provider ignores the free-text prompt and instead expects
        # incident_summary.py to pass structured context via generate_from_context.
        return (
            "AI analysis unavailable (mock provider active - no GROQ_API_KEY configured). "
            "See the deterministic summary below generated from rule-based logic."
        )

    def generate_from_context(self, incident_data: dict) -> str:
        lines = []
        lines.append(f"Incident Summary: {incident_data.get('title', 'Untitled incident')}")
        lines.append(
            f"Severity: {incident_data.get('severity', 'unknown').upper()} "
            f"(risk score: {incident_data.get('risk_score', 0)}/100)"
        )
        lines.append("")
        lines.append("Key Findings:")
        for alert_title in incident_data.get("alert_titles", [])[:8]:
            lines.append(f"  - {alert_title}")

        techniques = incident_data.get("mitre_techniques", [])
        if techniques:
            lines.append("")
            lines.append(f"MITRE ATT&CK techniques observed: {', '.join(techniques)}")

        lines.append("")
        lines.append("Likely Attack Sequence:")
        lines.append(
            "  Based on the correlated alert timeline, this incident likely represents "
            "a credential-focused attack progressing through the stages listed above. "
            "Review the incident timeline for exact ordering."
        )

        lines.append("")
        lines.append("False-Positive Considerations:")
        lines.append(
            "  Verify whether the affected user was traveling, using a VPN, or performing "
            "authorized administrative work before treating this as confirmed malicious activity."
        )

        return "\n".join(lines)


def get_deterministic_recommendations(severity: str) -> list[str]:
    base = [
        "Verify the affected user's identity through an out-of-band channel",
        "Review the full authentication timeline for the account",
        "Check source IP reputation and geolocation",
    ]
    if severity in ("high", "critical"):
        base.extend([
            "Consider requiring a password reset for the affected account",
            "Review recent privilege or group membership changes",
            "Escalate to Tier 2 / IR team if malicious intent is confirmed",
        ])
    return base
