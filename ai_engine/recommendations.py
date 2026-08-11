"""ai_engine/recommendations.py - Deterministic containment/investigation recommendations."""

from __future__ import annotations

from ai_engine.mock_provider import get_deterministic_recommendations
from mitre.mapper import get_technique


def build_investigation_checklist(mitre_techniques: list[str]) -> list[str]:
    checklist: list[str] = []
    for tid in mitre_techniques:
        technique = get_technique(tid)
        if technique:
            checklist.extend(technique.get("investigation_steps", []))
    # de-duplicate while preserving order
    seen = set()
    unique = []
    for item in checklist:
        if item not in seen:
            unique.append(item)
            seen.add(item)
    return unique


def build_containment_recommendations(severity: str) -> list[str]:
    return get_deterministic_recommendations(severity)
