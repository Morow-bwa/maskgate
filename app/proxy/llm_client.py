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


async def read_bounded_json(response: httpx.Response, max_bytes: int) -> Any:
    """Read provider JSON without allowing an unbounded response body."""
    declared_length = response.headers.get("content-length")
    if declared_length:
        try:
            if int(declared_length) > max_bytes:
                raise LLMUpstreamError(
                    "upstream_response_too_large",
                    "The upstream LLM response exceeded the configured size limit",
                )
        except ValueError:
            pass

    content = bytearray()
    async for chunk in response.aiter_bytes():
        content.extend(chunk)
        if len(content) > max_bytes:
            raise LLMUpstreamError(
                "upstream_response_too_large",
                "The upstream LLM response exceeded the configured size limit",
            )
    try:
        return json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LLMUpstreamError(
            "upstream_invalid_response", "The upstream LLM returned a non-JSON response"
        ) from exc


async def bounded_sse_lines(response: httpx.Response, max_bytes: int) -> AsyncIterator[str]:
    """Yield SSE lines while bounding the complete streamed provider response."""
    received = 0
    async for line in response.aiter_lines():
        received += len(line.encode("utf-8")) + 1
        if received > max_bytes:
            raise LLMUpstreamError(
                "upstream_response_too_large",
                "The upstream LLM stream exceeded the configured size limit",
            )
        yield line


class LLMClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 120,
        *,
        max_response_bytes: int = 8 * 1024 * 1024,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max(max_response_bytes, 1_024)
        self.transport = transport

    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self.transport,
            ) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                ) as response:
                    response_payload = await read_bounded_json(response, self.max_response_bytes)
                    return UpstreamResult(response.status_code, response_payload)
        except LLMUpstreamError:
            raise
        except httpx.TimeoutException as exc:
            raise LLMUpstreamError(
                "upstream_timeout", "The upstream LLM request timed out"
            ) from exc
        except httpx.HTTPError as exc:
            raise LLMUpstreamError(
                "upstream_unavailable", "The upstream LLM is unavailable"
            ) from exc

    async def complete_stream(self, payload: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        """Yield parsed OpenAI-compatible SSE events without buffering the answer."""
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self.transport,
            ) as client:
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
                    async for line in bounded_sse_lines(response, self.max_response_bytes):
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
            raise LLMUpstreamError(
                "upstream_unavailable", "The upstream LLM stream is unavailable"
            ) from exc
