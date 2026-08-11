"""
threat_intelligence/mock_provider.py
Deterministic, offline threat-intelligence provider used by default when no
API keys are configured. Uses reserved documentation IP ranges (RFC 5737) plus
a small hardcoded "known-malicious" demo list so detection rules and the
dashboard have realistic, reproducible enrichment data without any network
calls.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from core.validators import is_private_ip, is_reserved_demo_ip

# Curated demo "malicious" IPs (reserved TEST-NET ranges only - never real infra)
_KNOWN_MALICIOUS_DEMO_IPS = {
    "198.51.100.66": {"country": "RU", "asn": "AS64500", "isp": "Demo-BulletproofHost"},
    "203.0.113.13": {"country": "NG", "asn": "AS64510", "isp": "Demo-AnonProxy"},
    "198.51.100.99": {"country": "CN", "asn": "AS64520", "isp": "Demo-TorExit"},
}


def _deterministic_confidence(ip: str) -> int:
    """Derives a stable pseudo-random confidence score from the IP string."""
    digest = hashlib.sha256(ip.encode()).hexdigest()
    return int(digest[:2], 16) % 100


def lookup(ip: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()

    # RFC 5737 documentation/demo ranges represent "internet" attacker/user
    # IPs in this lab's sample data and must NOT be treated as private, even
    # though Python's ipaddress module classifies them as non-globally-routable.
    if is_private_ip(ip) and not is_reserved_demo_ip(ip):
        return {
            "ip": ip,
            "is_private": True,
            "country": None,
            "city": None,
            "asn": None,
            "isp": None,
            "latitude": None,
            "longitude": None,
            "reputation": "unknown",
            "malicious_count": 0,
            "suspicious_count": 0,
            "confidence_score": 0,
            "source": "mock",
            "last_checked": now,
        }

    if ip in _KNOWN_MALICIOUS_DEMO_IPS:
        info = _KNOWN_MALICIOUS_DEMO_IPS[ip]
        return {
            "ip": ip,
            "is_private": False,
            "country": info["country"],
            "city": None,
            "asn": info["asn"],
            "isp": info["isp"],
            "latitude": None,
            "longitude": None,
            "reputation": "malicious",
            "malicious_count": 12,
            "suspicious_count": 4,
            "confidence_score": 92,
            "source": "mock",
            "last_checked": now,
        }

    confidence = _deterministic_confidence(ip)
    reputation = "suspicious" if confidence > 80 else "clean"

    return {
        "ip": ip,
        "is_private": False,
        "country": "Unknown",
        "city": None,
        "asn": "AS00000",
        "isp": "Demo-ISP",
        "latitude": None,
        "longitude": None,
        "reputation": reputation,
        "malicious_count": 1 if reputation == "suspicious" else 0,
        "suspicious_count": 1 if reputation == "suspicious" else 0,
        "confidence_score": confidence,
        "source": "mock",
        "last_checked": now,
    }
