"""
tests/test_geoip_routing.py
Tests for GeoIP provider routing: mock vs live selection, private/reserved
IP protection, caching, and graceful fallback. All network calls are mocked
- no real internet access is used or required. Config is patched in-memory
(never written to disk) to keep tests fully isolated.
"""

from unittest.mock import patch

from core.config import load_config
from threat_intelligence import geoip


def _with_geoip_provider(monkeypatch, provider: str):
    """Patches the live config singleton's geoip_provider in-memory only."""
    cfg = load_config()
    monkeypatch.setattr(cfg.threat_intelligence, "geoip_provider", provider)
    return cfg


def test_mock_provider_used_by_default():
    result = geoip.resolve_geoip("198.51.100.66")
    assert result["source"] == "mock"
    assert result["lat"] is not None


def test_mock_provider_deterministic_for_same_ip():
    r1 = geoip.resolve_geoip("203.0.113.20")
    r2 = geoip.resolve_geoip("203.0.113.20")
    assert r1["city"] == r2["city"]
    assert r1["source"] == r2["source"] == "mock"


def test_private_ip_never_routed_to_live_provider(monkeypatch):
    _with_geoip_provider(monkeypatch, "live")
    with patch("threat_intelligence.geoip.live_geoip_lookup") as mock_live:
        result = geoip.resolve_geoip("10.0.0.5")
        mock_live.assert_not_called()
        assert result["source"] == "mock"


def test_reserved_demo_ip_never_routed_to_live_provider(monkeypatch):
    _with_geoip_provider(monkeypatch, "live")
    with patch("threat_intelligence.geoip.live_geoip_lookup") as mock_live:
        result = geoip.resolve_geoip("198.51.100.66")  # RFC5737 demo range
        mock_live.assert_not_called()
        assert result["source"] == "mock"


def test_live_provider_used_for_public_ip_when_configured(monkeypatch):
    _with_geoip_provider(monkeypatch, "live")
    fake_result = {"city": "Frankfurt", "country": "DE", "lat": 50.11, "lon": 8.68, "isp": "Test ISP"}
    with patch("threat_intelligence.geoip.live_geoip_lookup", return_value=fake_result) as mock_live:
        result = geoip.resolve_geoip("8.8.8.8")
        mock_live.assert_called_once()
        assert result["source"] == "live"
        assert result["city"] == "Frankfurt"


def test_live_provider_result_is_cached(monkeypatch):
    _with_geoip_provider(monkeypatch, "live")
    fake_result = {"city": "Tokyo", "country": "JP", "lat": 35.68, "lon": 139.69}
    with patch("threat_intelligence.geoip.live_geoip_lookup", return_value=fake_result) as mock_live:
        first = geoip.resolve_geoip("9.9.9.9")
        second = geoip.resolve_geoip("9.9.9.9")
        assert first["source"] == "live"
        assert second["source"] == "cache"
        mock_live.assert_called_once()  # second call served from cache, not a new HTTP request


def test_live_provider_failure_falls_back_to_mock(monkeypatch):
    _with_geoip_provider(monkeypatch, "live")
    with patch("threat_intelligence.geoip.live_geoip_lookup", return_value=None):
        result = geoip.resolve_geoip("1.1.1.1")
        assert result["source"] == "mock"
        assert result.get("fallback_reason") == "live provider unavailable"


def test_live_geoip_lookup_never_called_for_private_ip():
    """live_geoip_lookup itself must refuse private IPs even if called directly."""
    result = geoip.live_geoip_lookup("192.168.1.1")
    assert result is None
