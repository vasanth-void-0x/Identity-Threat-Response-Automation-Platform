"""ai_engine/prompts.py - Prompt templates for AI-assisted incident analysis."""

from __future__ import annotations

INCIDENT_ANALYSIS_PROMPT_TEMPLATE = """\
Analyze the following SOC incident and provide:
1. A brief incident summary
2. Key findings
3. Severity explanation
4. Likely attack sequence
5. Relevant MITRE ATT&CK techniques
6. Recommended investigation steps
7. Recommended containment actions (for analyst review only - do not imply automatic execution)
8. False-positive considerations

Incident title: {title}
Severity: {severity}
Risk score: {risk_score}/100
Affected user: {user}
Source IP(s): {source_ips}
Hosts: {hosts}
MITRE techniques: {mitre_techniques}

Related alerts (chronological):
{alert_summary}
"""


def build_incident_prompt(incident_data: dict) -> str:
    alert_lines = "\n".join(
        f"  - {a}" for a in incident_data.get("alert_titles", [])
    ) or "  (no alert detail available)"

    return INCIDENT_ANALYSIS_PROMPT_TEMPLATE.format(
        title=incident_data.get("title", ""),
        severity=incident_data.get("severity", "unknown"),
        risk_score=incident_data.get("risk_score", 0),
        user=incident_data.get("user", "unknown"),
        source_ips=", ".join(incident_data.get("source_ips", [])) or "none",
        hosts=", ".join(incident_data.get("hosts", [])) or "none",
        mitre_techniques=", ".join(incident_data.get("mitre_techniques", [])) or "none",
        alert_summary=alert_lines,
    )
