from __future__ import annotations

import time
import uuid
import json
from typing import Any, AsyncIterator

import httpx

from .llm_client import LLMUpstreamError, UpstreamResult


class GeminiClient:
    """Native Gemini generateContent adapter behind the OpenAI-compatible proxy."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 120,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    @staticmethod
    def _message_parts(content: Any) -> list[dict[str, str]]:
        if isinstance(content, str):
            return [{"text": content}]
        if isinstance(content, list):
            parts: list[dict[str, str]] = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                    parts.append({"text": item["text"]})
            return parts
        return []

    @classmethod
    def to_gemini_payload(cls, payload: dict[str, Any]) -> dict[str, Any]:
        contents: list[dict[str, Any]] = []
        system_parts: list[dict[str, str]] = []

        for message in payload.get("messages", []):
            role = message.get("role", "user")
            parts = cls._message_parts(message.get("content"))
            if not parts:
                continue
            if role == "system":
                system_parts.extend(parts)
                continue
            contents.append({"role": "model" if role == "assistant" else "user", "parts": parts})

        result: dict[str, Any] = {"contents": contents}
        if system_parts:
            result["systemInstruction"] = {"parts": system_parts}

        generation_config: dict[str, Any] = {}
        for source, target in (
            ("temperature", "temperature"),
            ("top_p", "topP"),
            ("max_tokens", "maxOutputTokens"),
            ("stop", "stopSequences"),
        ):
            if source in payload and payload[source] is not None:
                generation_config[target] = payload[source]
        if generation_config:
            result["generationConfig"] = generation_config
        return result

    @staticmethod
    def from_gemini_response(payload: dict[str, Any], model: str) -> dict[str, Any]:
        candidates = payload.get("candidates") or []
        candidate = candidates[0] if candidates else {}
        content = candidate.get("content") or {}
        parts = content.get("parts") or []
        text = "".join(part.get("text", "") for part in parts if isinstance(part, dict))
        finish_reason = candidate.get("finishReason", "STOP").lower()
        usage = payload.get("usageMetadata") or {}
        return {
            "id": f"chatcmpl-gemini-{uuid.uuid4().hex[:16]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop" if finish_reason == "stop" else finish_reason,
                }
            ],
            "usage": {
                "prompt_tokens": usage.get("promptTokenCount", 0),
                "completion_tokens": usage.get("candidatesTokenCount", 0),
                "total_tokens": usage.get("totalTokenCount", 0),
            },
        }

    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        model = payload.get("model") or "gemini-2.5-flash"
        url = f"{self.base_url}/models/{model}:generateContent"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            # Header form avoids putting the secret in URLs, access logs, or traces.
            headers["x-goog-api-key"] = self.api_key
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, transport=self.transport) as client:
                response = await client.post(url, headers=headers, json=self.to_gemini_payload(payload))
        except httpx.TimeoutException as exc:
            raise LLMUpstreamError("upstream_timeout", "The upstream Gemini request timed out") from exc
        except httpx.HTTPError as exc:
            raise LLMUpstreamError("upstream_unavailable", "The upstream Gemini service is unavailable") from exc

        try:
            response_payload = response.json()
        except ValueError as exc:
            raise LLMUpstreamError(
                "upstream_invalid_response", "The upstream Gemini service returned a non-JSON response"
            ) from exc

        if response.is_error:
            return UpstreamResult(response.status_code, response_payload)
        return UpstreamResult(response.status_code, self.from_gemini_response(response_payload, model))

    async def complete_stream(self, payload: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
        model = payload.get("model") or "gemini-2.5-flash"
        url = f"{self.base_url}/models/{model}:streamGenerateContent?alt=sse"
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self.api_key:
            headers["x-goog-api-key"] = self.api_key
        stream_id = f"chatcmpl-gemini-{uuid.uuid4().hex[:16]}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, transport=self.transport) as client:
                async with client.stream(
                    "POST",
                    url,
                    headers=headers,
                    json=self.to_gemini_payload(payload),
                ) as response:
                    if response.is_error:
                        raise LLMUpstreamError(
                            "upstream_error",
                            "The upstream Gemini service rejected the streaming request",
                        )
                    async for line in response.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        try:
                            chunk = json.loads(line[5:].strip())
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(chunk, dict):
                            continue
                        candidates = chunk.get("candidates") or []
                        candidate = candidates[0] if candidates else {}
                        content = candidate.get("content") or {}
                        parts = content.get("parts") or []
                        text = "".join(
                            part.get("text", "") for part in parts if isinstance(part, dict)
                        )
                        finish_reason = candidate.get("finishReason")
                        yield {
                            "id": stream_id,
                            "object": "chat.completion.chunk",
                            "created": int(time.time()),
                            "model": model,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"role": "assistant", "content": text},
                                    "finish_reason": finish_reason.lower() if isinstance(finish_reason, str) else None,
                                }
                            ],
                        }
        except LLMUpstreamError:
            raise
        except httpx.TimeoutException as exc:
            raise LLMUpstreamError("upstream_timeout", "The upstream Gemini stream timed out") from exc
        except httpx.HTTPError as exc:
            raise LLMUpstreamError("upstream_unavailable", "The upstream Gemini stream is unavailable") from exc
