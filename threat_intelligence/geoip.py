"""
threat_intelligence/geoip.py
GeoIP lookups for event enrichment and the dashboard's attack source map.
Defaults to a deterministic mock provider; ip-api.com free tier can be
enabled for real lookups on public IPs (no key required, but rate-limited -
kept optional and off by default via threat_intelligence.geoip_provider).

resolve_geoip() is the single entry point callers should use - it respects
the configured provider, caches live results, and always falls back to the
mock provider on any failure so the dashboard never breaks when offline.
"""

from __future__ import annotations

import hashlib

from core.logger import get_logger
from core.validators import is_private_ip, is_reserved_demo_ip, is_valid_ip

logger = get_logger(__name__)

_DEMO_LOCATIONS = [
    {"city": "Chennai", "country": "IN", "lat": 13.0827, "lon": 80.2707},
    {"city": "Bangalore", "country": "IN", "lat": 12.9716, "lon": 77.5946},
    {"city": "Moscow", "country": "RU", "lat": 55.7558, "lon": 37.6173},
    {"city": "Lagos", "country": "NG", "lat": 6.5244, "lon": 3.3792},
    {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
]


def mock_geoip_lookup(ip: str) -> dict:
    if is_private_ip(ip) and not is_reserved_demo_ip(ip):
        return {"city": "Internal", "country": "LAN", "lat": None, "lon": None}
    idx = int(hashlib.sha256(ip.encode()).hexdigest(), 16) % len(_DEMO_LOCATIONS)
    return dict(_DEMO_LOCATIONS[idx])


def live_geoip_lookup(ip: str, timeout: int = 5) -> dict | None:
    """
    Optional real lookup via the HTTPS ipwho.is endpoint (no API key required).
    Never invoked for private or reserved/demo IP ranges - see resolve_geoip().
    """
    if is_private_ip(ip):
        return None
    try:
        import requests
        resp = requests.get(f"https://ipwho.is/{ip}", timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("success") is False:
            return None
        return {
            "city": data.get("city"),
            "country": data.get("country_code"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "isp": (data.get("connection") or {}).get("isp"),
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Live GeoIP lookup failed for %s: %s", ip, exc)
        return None


def resolve_geoip(ip: str) -> dict:
    """
    Single entry point for all GeoIP lookups. Respects the configured
    provider (threat_intelligence.geoip_provider: "mock" | "live"),
    caches live results, and always includes a "source" field so callers
    (and the dashboard) can clearly label whether a location is
    simulated, cached, or a genuine live lookup.

    Never presents mock coordinates as real attacker locations - the
    "source" field must be surfaced in the UI wherever this is displayed.
    """
    from core.config import load_config
    cfg = load_config().threat_intelligence

    if not is_valid_ip(ip):
        return {"city": None, "country": None, "lat": None, "lon": None,
                "source": "invalid", "fallback_reason": "invalid IP address"}

    # Demo/reserved (RFC 5737) and genuinely private IPs never go to a live
    # provider - either they're fictional lab addresses or truly internal.
    demo_or_private = is_private_ip(ip) or is_reserved_demo_ip(ip)

    if cfg.geoip_provider != "live" or demo_or_private:
        result = mock_geoip_lookup(ip)
        result["source"] = "mock"
        return result

    from threat_intelligence import cache as ti_cache
    cache_key = f"geoip:{ip}"

    try:
        cached = ti_cache.get_cached(cache_key, cfg.cache_ttl_seconds)
        if cached:
            cached_result = dict(cached)
            cached_result["source"] = "cache"
            return cached_result
    except Exception as exc:  # noqa: BLE001
        logger.debug("GeoIP cache unavailable: %s", exc)

    live = live_geoip_lookup(ip, timeout=cfg.request_timeout_seconds)
    if live and live.get("lat") is not None and live.get("lon") is not None:
        live_result = dict(live)
        try:
            ti_cache.set_cached(cache_key, live_result)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to cache GeoIP result: %s", exc)
        live_result["source"] = "live"
        return live_result

    # Live provider failed or returned nothing usable - fall back gracefully.
    logger.info("Live GeoIP unavailable for %s, falling back to mock location", ip)
    fallback = mock_geoip_lookup(ip)
    fallback["source"] = "mock"
    fallback["fallback_reason"] = "live provider unavailable"
    return fallback
