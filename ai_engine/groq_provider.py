"""
ai_engine/groq_provider.py
Optional Groq LLM provider for AI-assisted incident analysis. Only used when
ai.provider == "groq" AND GROQ_API_KEY is configured. On any failure, callers
fall back to the mock provider - AI output is always an analyst aid only and
never auto-triggers a response action.
"""

from __future__ import annotations

import requests

from ai_engine.provider import AIProvider
from core.exceptions import ITRAPBaseException
from core.logger import get_logger

logger = get_logger(__name__)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


class GroqProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        if not api_key:
            raise ITRAPBaseException("Groq API key not configured")
        self.api_key = api_key
        self.model = model

    def generate_incident_analysis(self, prompt: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": (
                    "You are a SOC Tier-2 analyst assistant. Provide concise, factual incident "
                    "analysis strictly from the data given. Never recommend or imply automatic "
                    "execution of containment actions - only provide recommendations for human review."
                )},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 700,
        }
        try:
            resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001
            logger.warning("Groq AI provider failed: %s", exc)
            raise
