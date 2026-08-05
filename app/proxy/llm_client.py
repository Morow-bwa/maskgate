from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, AsyncIterator

import httpx


@dataclass(frozen=True, slots=True)
class UpstreamResult:
    status_code: int
    payload: Any


class LLMUpstreamError(Exception):
    def __init__(self, error_type: str, message: str) -> None:
        self.error_type = error_type
        self.message = message
        super().__init__(message)


class LLMClient:
    def __init__(self, base_url: str, api_key: str, timeout_seconds: float = 120) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise LLMUpstreamError("upstream_timeout", "The upstream LLM request timed out") from exc
        except httpx.HTTPError as exc:
            raise LLMUpstreamError("upstream_unavailable", "The upstream LLM is unavailable") from exc

        try:
            response_payload = response.json()
        except ValueError as exc:
            raise LLMUpstreamError(
                "upstream_invalid_response", "The upstream LLM returned a non-JSON response"
            ) from exc
        return UpstreamResult(response.status_code, response_payload)

    async def complete_stream(self, payload: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        """Yield parsed OpenAI-compatible SSE events without buffering the answer."""
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as response:
                    if response.is_error:
                        raise LLMUpstreamError(
                            "upstream_error",
                            "The upstream LLM rejected the streaming request",
                        )
                    async for line in response.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            return
                        try:
                            event = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(event, dict):
                            yield event
        except LLMUpstreamError:
            raise
        except httpx.TimeoutException as exc:
            raise LLMUpstreamError("upstream_timeout", "The upstream LLM stream timed out") from exc
        except httpx.HTTPError as exc:
            raise LLMUpstreamError("upstream_unavailable", "The upstream LLM stream is unavailable") from exc
