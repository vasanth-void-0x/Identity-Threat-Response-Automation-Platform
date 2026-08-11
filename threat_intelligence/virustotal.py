"""
threat_intelligence/virustotal.py
Optional VirusTotal IP reputation provider. Only activated when
threat_intelligence.provider == "virustotal" AND VIRUSTOTAL_API_KEY is set
via environment variable / .env. Never called for private IP addresses.
"""

from __future__ import annotations

from datetime import datetime, timezone

import requests

from core.exceptions import ThreatIntelError
from core.logger import get_logger
from core.validators import is_private_ip

logger = get_logger(__name__)

BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"


def lookup(ip: str, api_key: str, timeout: int = 5, max_retries: int = 2) -> dict:
    if is_private_ip(ip):
        raise ThreatIntelError("Refusing to send a private IP address to an external API")
    if not api_key:
        raise ThreatIntelError("VirusTotal API key is not configured")

    headers = {"x-apikey": api_key}
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(f"{BASE_URL}/{ip}", headers=headers, timeout=timeout)
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            reputation = "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "clean")

            return {
                "ip": ip,
                "is_private": False,
                "country": data.get("country"),
                "asn": data.get("asn"),
                "isp": data.get("as_owner"),
                "reputation": reputation,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "confidence_score": min(100, (malicious * 10) + (suspicious * 5)),
                "source": "virustotal",
                "last_checked": datetime.now(timezone.utc).isoformat(),
            }
        except requests.RequestException as exc:
            last_exc = exc
            logger.warning("VirusTotal lookup attempt %d failed for %s: %s", attempt + 1, ip, exc)

    raise ThreatIntelError(f"VirusTotal lookup failed for {ip}: {last_exc}")
