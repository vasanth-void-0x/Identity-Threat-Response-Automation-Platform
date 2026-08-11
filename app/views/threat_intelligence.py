"""app/views/threat_intelligence.py - Safe on-demand IP reputation lookup page."""

from __future__ import annotations

import streamlit as st

from app.theme import page_header
from core.config import load_config
from core.validators import is_private_ip, is_reserved_demo_ip, is_valid_ip
from threat_intelligence.manager import ThreatIntelManager


def render() -> None:
    page_header("Threat Intelligence", "On-demand IP reputation, ASN and GeoIP context with private-IP safeguards.")

    cfg = load_config().threat_intelligence
    st.write(f"**Active provider:** `{cfg.provider}`")
    if cfg.provider != "mock":
        key_configured = bool(cfg.virustotal_api_key or cfg.abuseipdb_api_key)
        st.write(f"**API key configured:** {'✅ Yes' if key_configured else '❌ No (will fall back to mock)'}")

    left, right = st.columns([1, 1.65], gap="large")
    with left:
        ip_input = st.text_input("Public IP address", placeholder="8.8.8.8")

    if ip_input:
        if not is_valid_ip(ip_input):
            st.error("Invalid IP address format.")
        elif is_private_ip(ip_input) and not is_reserved_demo_ip(ip_input):
            st.warning("Private IP addresses are never sent to external providers - showing internal classification only.")
            manager = ThreatIntelManager()
            with right:
                st.json(manager.lookup_ip(ip_input))
        else:
            with st.spinner("Looking up IP reputation..."):
                manager = ThreatIntelManager()
                result = manager.lookup_ip(ip_input)
            with right:
                reputation = result.get("reputation", "unknown")
                color = {"malicious": "🔴", "suspicious": "🟠", "clean": "🟢"}.get(reputation, "⚪")
                st.markdown(f"### {color} Reputation · **{reputation.upper()}**")
                st.json(result)
    else:
        with right:
            st.info("Enter a public IP to retrieve reputation and network context. Private addresses remain local.")
