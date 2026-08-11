"""
threat_intelligence/manager.py
Single entry point for IP enrichment. Selects the configured provider
(mock/virustotal/abuseipdb), applies SQLite caching, and always falls back
to the mock provider on any error so the platform keeps working without
API keys or network access.
"""

from __future__ import annotations

from core.config import load_config
from core.exceptions import ThreatIntelError
from core.logger import get_logger
from core.validators import is_private_ip, is_reserved_demo_ip
from threat_intelligence import abuseipdb, cache, mock_provider, virustotal

logger = get_logger(__name__)


class ThreatIntelManager:
    def __init__(self):
        self.cfg = load_config().threat_intelligence

    def lookup_ip(self, ip: str) -> dict:
        if not ip:
            return {"ip": ip, "reputation": "unknown", "source": "none"}

        if is_private_ip(ip) and not is_reserved_demo_ip(ip):
            return mock_provider.lookup(ip)

        try:
            cached = cache.get_cached(ip, self.cfg.cache_ttl_seconds)
            if cached:
                return cached
        except Exception as exc:  # noqa: BLE001
            logger.debug("Threat intel cache unavailable: %s", exc)

        result = self._lookup_from_provider(ip)

        try:
            cache.set_cached(ip, result)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to write threat intel cache: %s", exc)

        return result

    def _lookup_from_provider(self, ip: str) -> dict:
        provider = self.cfg.provider

        try:
            if provider == "virustotal" and self.cfg.virustotal_api_key:
                return virustotal.lookup(
                    ip, self.cfg.virustotal_api_key,
                    timeout=self.cfg.request_timeout_seconds,
                    max_retries=self.cfg.max_retries,
                )
            if provider == "abuseipdb" and self.cfg.abuseipdb_api_key:
                return abuseipdb.lookup(
                    ip, self.cfg.abuseipdb_api_key,
                    timeout=self.cfg.request_timeout_seconds,
                    max_retries=self.cfg.max_retries,
                )
        except ThreatIntelError as exc:
            logger.warning("Threat intel provider '%s' failed, falling back to mock: %s", provider, exc)

        return mock_provider.lookup(ip)
