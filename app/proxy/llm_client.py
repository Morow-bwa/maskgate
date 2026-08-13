from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, AsyncIterator

import httpx

from app.privacy.detection import DetectorEnsemble
from app.privacy.models import DetectorProfile
from app.privacy.wire import FinalWirePrivacyGuard, PrivacyCheckedPayload


@dataclass(frozen=True, slots=True)
class UpstreamResult:
    status_code: int
    payload: Any


class LLMUpstreamError(Exception):
    def __init__(self, error_type: str, message: str) -> None:
        self.error_type = error_type
        self.message = message
        super().__init__(message)


_PUBLIC_UPSTREAM_MESSAGES = {
    "invalid_model": "The provider model is invalid",
    "upstream_error": "The upstream provider rejected the request",
    "upstream_invalid_response": "The upstream LLM returned an invalid response",
    "upstream_invalid_stream": "The upstream LLM returned an invalid stream",
    "upstream_response_too_large": "The upstream LLM response exceeded the configured size limit",
    "upstream_timeout": "The upstream LLM request timed out",
    "upstream_unavailable": "The upstream LLM is unavailable",
}


def public_upstream_error(error_type: str) -> tuple[str, str]:
    """Return a bounded client-safe error without reflecting provider text."""

    safe_type = error_type if error_type in _PUBLIC_UPSTREAM_MESSAGES else "upstream_error"
    return safe_type, _PUBLIC_UPSTREAM_MESSAGES[safe_type]


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


async def bounded_sse_data(response: httpx.Response, max_bytes: int) -> AsyncIterator[str]:
    """Parse bounded SSE frames, including events with multiple data lines."""

    data_lines: list[str] = []
    async for line in bounded_sse_lines(response, max_bytes):
        if line == "":
            if data_lines:
                yield "\n".join(data_lines)
                data_lines.clear()
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if not separator:
            raise LLMUpstreamError(
                "upstream_invalid_stream",
                "The upstream LLM returned a malformed SSE stream",
            )
        if field == "data":
            data_lines.append(value[1:] if value.startswith(" ") else value)
        elif field not in {"event", "id", "retry"}:
            raise LLMUpstreamError(
                "upstream_invalid_stream",
                "The upstream LLM returned an unsupported SSE field",
            )
    if data_lines:
        yield "\n".join(data_lines)


class LLMClient:
    accepts_privacy_checked_payload = True

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

    def prepare_request(
        self, payload: dict[str, Any], *, stream: bool = False
    ) -> tuple[str, str, dict[str, Any]]:
        return "openai-compatible-chat", "/chat/completions", payload

    @staticmethod
    def _checked(payload: PrivacyCheckedPayload | dict[str, Any]) -> PrivacyCheckedPayload:
        if isinstance(payload, PrivacyCheckedPayload):
            return payload
        # Direct library callers still receive the same final guard. Application
        # flows prepare their checked payload with the request vault so known
        # opaque tokens can be approved explicitly.
        detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
        return FinalWirePrivacyGuard(detector).check(
            provider="openai-compatible-chat",
            target="/chat/completions",
            payload=payload,
        )

    async def complete(self, payload: PrivacyCheckedPayload | dict[str, Any]) -> UpstreamResult:
        checked = self._checked(payload)
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
                    f"{self.base_url}{checked.target or '/chat/completions'}",
                    headers=headers,
                    content=checked.body,
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

    async def complete_stream(
        self, payload: PrivacyCheckedPayload | dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield parsed OpenAI-compatible SSE events without buffering the answer."""
        checked = self._checked(payload)
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
                    f"{self.base_url}{checked.target or '/chat/completions'}",
                    headers=headers,
                    content=checked.body,
                ) as response:
                    if response.is_error:
                        raise LLMUpstreamError(
                            "upstream_error",
                            "The upstream LLM rejected the streaming request",
                        )
                    async for data in bounded_sse_data(response, self.max_response_bytes):
                        data = data.strip()
                        if data == "[DONE]":
                            return
                        try:
                            event = json.loads(data)
                        except json.JSONDecodeError as exc:
                            raise LLMUpstreamError(
                                "upstream_invalid_stream",
                                "The upstream LLM returned malformed SSE JSON",
                            ) from exc
                        if not isinstance(event, dict):
                            raise LLMUpstreamError(
                                "upstream_invalid_stream",
                                "The upstream LLM returned an invalid SSE event",
                            )
                        yield event
        except LLMUpstreamError:
            raise
        except httpx.TimeoutException as exc:
            raise LLMUpstreamError("upstream_timeout", "The upstream LLM stream timed out") from exc
        except httpx.HTTPError as exc:
            raise LLMUpstreamError(
                "upstream_unavailable", "The upstream LLM stream is unavailable"
            ) from exc
