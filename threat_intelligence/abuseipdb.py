"""
threat_intelligence/abuseipdb.py
Optional AbuseIPDB IP reputation provider. Only activated when
threat_intelligence.provider == "abuseipdb" AND ABUSEIPDB_API_KEY is set.
Never called for private IP addresses.
"""

from __future__ import annotations

from datetime import datetime, timezone

import requests

from core.exceptions import ThreatIntelError
from core.logger import get_logger
from core.validators import is_private_ip

logger = get_logger(__name__)

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def lookup(ip: str, api_key: str, timeout: int = 5, max_retries: int = 2) -> dict:
    if is_private_ip(ip):
        raise ThreatIntelError("Refusing to send a private IP address to an external API")
    if not api_key:
        raise ThreatIntelError("AbuseIPDB API key is not configured")

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(BASE_URL, headers=headers, params=params, timeout=timeout)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            reputation = "malicious" if score >= 75 else ("suspicious" if score >= 25 else "clean")

            return {
                "ip": ip,
                "is_private": False,
                "country": data.get("countryCode"),
                "asn": None,
                "isp": data.get("isp"),
                "reputation": reputation,
                "malicious_count": data.get("totalReports", 0),
                "suspicious_count": 0,
                "confidence_score": score,
                "source": "abuseipdb",
                "last_checked": datetime.now(timezone.utc).isoformat(),
            }
        except requests.RequestException as exc:
            last_exc = exc
            logger.warning("AbuseIPDB lookup attempt %d failed for %s: %s", attempt + 1, ip, exc)

    raise ThreatIntelError(f"AbuseIPDB lookup failed for {ip}: {last_exc}")
