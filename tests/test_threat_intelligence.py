"""tests/test_threat_intelligence.py - Tests for threat intel mock provider and manager (no network calls)."""

from threat_intelligence import mock_provider
from threat_intelligence.geoip import mock_geoip_lookup
from threat_intelligence.manager import ThreatIntelManager


def test_mock_provider_private_ip():
    result = mock_provider.lookup("192.168.1.5")
    assert result["is_private"] is True
    assert result["reputation"] == "unknown"


def test_mock_provider_known_malicious_ip():
    result = mock_provider.lookup("198.51.100.66")
    assert result["reputation"] == "malicious"
    assert result["confidence_score"] > 80


def test_mock_provider_deterministic():
    r1 = mock_provider.lookup("203.0.113.200")
    r2 = mock_provider.lookup("203.0.113.200")
    assert r1["confidence_score"] == r2["confidence_score"]


def test_manager_falls_back_to_mock_with_no_key():
    manager = ThreatIntelManager()
    result = manager.lookup_ip("198.51.100.66")
    assert result["reputation"] == "malicious"


def test_manager_handles_empty_ip():
    manager = ThreatIntelManager()
    result = manager.lookup_ip("")
    assert result["reputation"] == "unknown"


def test_geoip_genuinely_private_ip_has_no_coordinates():
    result = mock_geoip_lookup("10.1.2.3")
    assert result["city"] == "Internal"
    assert result["lat"] is None


def test_geoip_reserved_demo_ip_is_geolocatable():
    result = mock_geoip_lookup("198.51.100.66")
    assert result["lat"] is not None
    assert result["lon"] is not None
    assert result["city"] != "Internal"
