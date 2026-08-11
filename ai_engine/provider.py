"""ai_engine/provider.py - Abstract interface all AI providers implement."""

from __future__ import annotations

from abc import ABC, abstractmethod


class AIProvider(ABC):
    @abstractmethod
    def generate_incident_analysis(self, prompt: str) -> str:
        """Returns a text analysis given a fully-constructed prompt. Never auto-triggers actions."""
        raise NotImplementedError
