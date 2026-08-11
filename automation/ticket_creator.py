"""
automation/ticket_creator.py
Simulated SOC ticket creation. No real ticketing system (Jira/ServiceNow) is
integrated in this lab build - this always records a simulated ticket and
returns a mock ticket ID, keeping the incident workflow demoable end-to-end
without external dependencies.
"""

from __future__ import annotations

import uuid

from automation.simulation import simulated_result


def create_ticket(incident_id: str, title: str, severity: str) -> str:
    ticket_id = f"TCKT-{uuid.uuid4().hex[:6].upper()}"
    return (
        f"[SIMULATION] SOC ticket {ticket_id} created for incident {incident_id} "
        f"('{title}', severity: {severity}). No real ticketing system is integrated in this lab build."
    )
