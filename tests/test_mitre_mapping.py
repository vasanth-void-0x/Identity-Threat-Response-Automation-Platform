"""tests/test_mitre_mapping.py - Tests for MITRE ATT&CK mapping module."""

from mitre.mapper import get_technique, get_technique_summary, map_techniques, technique_frequency


def test_get_known_technique():
    t = get_technique("T1110")
    assert t is not None
    assert t["name"] == "Brute Force"


def test_get_unknown_technique_returns_none():
    assert get_technique("T9999") is None


def test_get_technique_summary():
    summary = get_technique_summary("T1110")
    assert "T1110" in summary
    assert "Brute Force" in summary


def test_map_techniques_handles_unknown():
    result = map_techniques(["T1110", "T9999"])
    assert result[0]["name"] == "Brute Force"
    assert result[1]["name"] == "Unknown technique"


def test_technique_frequency():
    freq = technique_frequency([["T1110", "T1078"], ["T1110"]])
    assert freq["T1110"] == 2
    assert freq["T1078"] == 1
