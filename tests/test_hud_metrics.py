"""Regression coverage for the Overview HUD's dynamic threat-level scoring
and metric-sparkline bucketing (app/utils/data_mode.py additions)."""

from app.utils.data_mode import bucketed_counts, latest_incident, risk_level_for_score, threat_level


def test_risk_level_bounds_match_gauge_thresholds():
    assert risk_level_for_score(0) == "LOW"
    assert risk_level_for_score(29) == "LOW"
    assert risk_level_for_score(30) == "MEDIUM"
    assert risk_level_for_score(59) == "MEDIUM"
    assert risk_level_for_score(60) == "HIGH"
    assert risk_level_for_score(79) == "HIGH"
    assert risk_level_for_score(80) == "CRITICAL"
    assert risk_level_for_score(100) == "CRITICAL"


def test_threat_level_uses_highest_score_and_counts_correctly():
    incidents = [
        {"risk_score": 20, "severity": "low"},
        {"risk_score": 95, "severity": "critical"},
        {"risk_score": 65, "severity": "high"},
    ]
    result = threat_level(incidents)
    assert result["level"] == "CRITICAL"
    assert result["highest_score"] == 95
    assert result["critical_count"] == 1
    assert result["high_count"] == 1


def test_threat_level_empty_incidents_is_low_and_never_crashes():
    result = threat_level([])
    assert result["level"] == "LOW"
    assert result["highest_score"] == 0
    assert result["critical_count"] == 0


def test_latest_incident_picks_most_recent_created_at():
    incidents = [
        {"incident_id": "old", "created_at": "2026-01-01T00:00:00Z"},
        {"incident_id": "new", "created_at": "2026-06-01T00:00:00Z"},
    ]
    assert latest_incident(incidents)["incident_id"] == "new"


def test_latest_incident_empty_list_returns_none():
    assert latest_incident([]) is None


def test_bucketed_counts_empty_and_single_item_are_safe():
    assert bucketed_counts([]) == []
    assert bucketed_counts([{"created_at": "2026-01-01T00:00:00Z"}]) == []


def test_bucketed_counts_sums_to_total_items():
    items = [{"created_at": f"2026-01-{day:02d}T00:00:00Z"} for day in range(1, 11)]
    buckets = bucketed_counts(items, buckets=4)
    assert sum(buckets) == len(items)
    assert len(buckets) == 4
