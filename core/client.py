"""
Target API Client - Sends attack payloads to the target LLM.
Supports OpenAI-compatible APIs, Anthropic, and local Ollama.
"""

import time
import httpx
from dataclasses import dataclass
from typing import Optional

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider."""
    content: str
    success: bool
    latency: float
    tokens_used: int
    error: Optional[str] = None
    raw: Optional[dict] = None


class TargetClient:
    """Unified client for testing any LLM endpoint."""

    def __init__(self, target: str, api_key: str = "", model: str = "",
                 system_prompt: str = "", timeout: int = 30):
        self.target = target
        self.api_key = api_key
        self.model = model
        self.system_prompt = system_prompt
        self.timeout = timeout
        self.request_count = 0

        # Determine provider type
        if target == "anthropic":
            self.provider = "anthropic"
            if not HAS_ANTHROPIC:
                raise ImportError("anthropic package required: pip install anthropic")
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            # OpenAI-compatible (works with OpenAI, Ollama, vLLM, LiteLLM, etc.)
            self.provider = "openai_compat"
            self.http_client = httpx.Client(timeout=timeout)

    def send(self, prompt: str, override_system: str = "") -> LLMResponse:
        """Send a prompt to the target and get the response."""
        system = override_system or self.system_prompt
        self.request_count += 1

        try:
            if self.provider == "anthropic":
                return self._send_anthropic(prompt, system)
            else:
                return self._send_openai_compat(prompt, system)
        except Exception as e:
            return LLMResponse(
                content="",
                success=False,
                latency=0,
                tokens_used=0,
                error=str(e)
            )

    def send_multi_turn(self, messages: list[dict], override_system: str = "") -> LLMResponse:
        """Send a multi-turn conversation."""
        system = override_system or self.system_prompt
        self.request_count += 1

        try:
            if self.provider == "anthropic":
                return self._send_anthropic_multi(messages, system)
            else:
                return self._send_openai_compat_multi(messages, system)
        except Exception as e:
            return LLMResponse(
                content="",
                success=False,
                latency=0,
                tokens_used=0,
                error=str(e)
            )

    def _send_anthropic(self, prompt: str, system: str) -> LLMResponse:
        start = time.time()
        kwargs = {
            "model": self.model or "claude-sonnet-4-20250514",
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}]
        }
        if system:
            kwargs["system"] = system

        response = self.client.messages.create(**kwargs)
        latency = time.time() - start

        return LLMResponse(
            content=response.content[0].text,
            success=True,
            latency=latency,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            raw={"id": response.id, "model": response.model}
        )

    def _send_anthropic_multi(self, messages: list[dict], system: str) -> LLMResponse:
        start = time.time()
        kwargs = {
            "model": self.model or "claude-sonnet-4-20250514",
            "max_tokens": 2048,
            "messages": messages
        }
        if system:
            kwargs["system"] = system

        response = self.client.messages.create(**kwargs)
        latency = time.time() - start

        return LLMResponse(
            content=response.content[0].text,
            success=True,
            latency=latency,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            raw={"id": response.id}
        )

    def _send_openai_compat(self, prompt: str, system: str) -> LLMResponse:
        start = time.time()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model or "gpt-4",
            "messages": messages,
            "max_tokens": 2048,
            "temperature": 0.7
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        resp = self.http_client.post(self.target, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        latency = time.time() - start

        content = data["choices"][0]["message"]["content"]
        tokens = data.get("usage", {})

        return LLMResponse(
            content=content,
            success=True,
            latency=latency,
            tokens_used=tokens.get("total_tokens", 0),
            raw=data
        )

    def _send_openai_compat_multi(self, messages: list[dict], system: str) -> LLMResponse:
        start = time.time()
        full_messages = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)

        payload = {
            "model": self.model or "gpt-4",
            "messages": full_messages,
            "max_tokens": 2048,
            "temperature": 0.7
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        resp = self.http_client.post(self.target, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        latency = time.time() - start

        content = data["choices"][0]["message"]["content"]
        tokens = data.get("usage", {})

        return LLMResponse(
            content=content,
            success=True,
            latency=latency,
            tokens_used=tokens.get("total_tokens", 0),
            raw=data
        )
