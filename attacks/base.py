"""
Base class for all attack modules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from core.client import TargetClient
from core.analyzer import AnalysisResult, ResponseAnalyzer


@dataclass
class AttackPayload:
    """A single attack payload with metadata."""
    name: str
    prompt: str
    category: str
    description: str
    multi_turn: bool = False
    messages: list = None  # For multi-turn attacks
    expected_behavior: str = ""
    forbidden_topic: str = ""
    expected_output: str = ""

    def __post_init__(self):
        if self.messages is None:
            self.messages = []


class BaseAttack(ABC):
    """Abstract base class for attack modules."""

    name: str = "base"
    category: str = "misc"
    description: str = ""

    def __init__(self, client: TargetClient, analyzer: ResponseAnalyzer, config: dict):
        self.client = client
        self.analyzer = analyzer
        self.config = config

    @abstractmethod
    def get_payloads(self) -> list[AttackPayload]:
        """Return all attack payloads for this module."""
        pass

    def run(self, quick: bool = False) -> list[AnalysisResult]:
        """Execute all payloads and return results."""
        payloads = self.get_payloads()

        if quick:
            max_payloads = self.config.get("scan", {}).get("quick_mode_payloads", 5)
            payloads = payloads[:max_payloads]

        results = []
        for payload in payloads:
            result = self._execute_payload(payload)
            if result:
                results.append(result)

        return results

    def _execute_payload(self, payload: AttackPayload) -> AnalysisResult:
        """Execute a single payload and analyze the response."""
        if payload.multi_turn and payload.messages:
            response = self.client.send_multi_turn(payload.messages)
        else:
            response = self.client.send(payload.prompt)

        if not response.success:
            return AnalysisResult(
                verdict="error",
                confidence=0,
                evidence=f"Request failed: {response.error}",
                payload=payload.prompt[:500],
                response="",
                category=payload.category,
                attack_name=payload.name,
                latency=response.latency
            )

        return self._analyze(payload, response.content, response.latency)

    @abstractmethod
    def _analyze(self, payload: AttackPayload, response: str, latency: float) -> AnalysisResult:
        """Analyze the response for this specific attack type."""
        pass
