"""mitre/mapper.py - Loads MITRE ATT&CK technique metadata and maps incidents/alerts to it."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

MITRE_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def load_techniques() -> dict:
    with open(MITRE_DIR / "techniques.json", "r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_tactics() -> dict:
    with open(MITRE_DIR / "tactics.json", "r", encoding="utf-8") as f:
        return json.load(f)


def get_technique(technique_id: str) -> dict | None:
    return load_techniques().get(technique_id)


def get_technique_summary(technique_id: str) -> str:
    t = get_technique(technique_id)
    if not t:
        return technique_id
    return f"{technique_id} - {t['name']} ({t['tactic']})"


def map_techniques(technique_ids: list[str]) -> list[dict]:
    techniques = load_techniques()
    result = []
    for tid in technique_ids:
        t = techniques.get(tid)
        if t:
            result.append({"id": tid, **t})
        else:
            result.append({"id": tid, "name": "Unknown technique", "tactic": "Unknown",
                            "description": "", "detection_source": "", "investigation_steps": []})
    return result


def technique_frequency(all_incident_techniques: list[list[str]]) -> dict[str, int]:
    """Given a list of technique-id lists (one per incident), returns counts per technique."""
    freq: dict[str, int] = {}
    for techniques in all_incident_techniques:
        for tid in techniques:
            freq[tid] = freq.get(tid, 0) + 1
    return freq
