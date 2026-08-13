from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any, AsyncIterator

import httpx

from app.privacy.detection import DetectorEnsemble, LegacyEntityDetectorAdapter
from app.privacy.models import DetectorProfile
from app.privacy.wire import FinalWirePrivacyGuard, PrivacyCheckedPayload

from .llm_client import LLMUpstreamError, UpstreamResult, bounded_sse_data, read_bounded_json

MODEL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class GeminiClient:
    """Native Gemini generateContent adapter behind the OpenAI-compatible proxy."""

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

    @staticmethod
    def _normalized_model(value: Any) -> str:
        model = str(value or "gemini-2.5-flash")
        if model.startswith("models/"):
            model = model.removeprefix("models/")
        if not MODEL_NAME_PATTERN.fullmatch(model):
            raise LLMUpstreamError(
                "invalid_model",
                "The provider model name contains unsupported characters",
            )
        return model

    @staticmethod
    def _message_parts(content: Any) -> list[dict[str, str]]:
        if isinstance(content, str):
            return [{"text": content}]
        if isinstance(content, list):
            parts: list[dict[str, str]] = []
            for item in content:
                if (
                    isinstance(item, dict)
                    and item.get("type") == "text"
                    and isinstance(item.get("text"), str)
                ):
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

    def prepare_request(
        self, payload: dict[str, Any], *, stream: bool = False
    ) -> tuple[str, str, dict[str, Any]]:
        model = self._normalized_model(payload.get("model"))
        operation = "streamGenerateContent?alt=sse" if stream else "generateContent"
        return (
            "gemini-generate-content",
            f"/models/{model}:{operation}",
            self.to_gemini_payload(payload),
        )

    def _checked(
        self, payload: PrivacyCheckedPayload | dict[str, Any], *, stream: bool
    ) -> PrivacyCheckedPayload:
        if isinstance(payload, PrivacyCheckedPayload):
            return payload
        provider, target, body = self.prepare_request(payload, stream=stream)
        detector = LegacyEntityDetectorAdapter(
            DetectorEnsemble(profile=DetectorProfile.STRICT)
        )
        return FinalWirePrivacyGuard(detector).check(
            provider=provider,
            target=target,
            payload=body,
        )

    @staticmethod
    def _model_from_target(target: str) -> str:
        marker = "/models/"
        if marker not in target or ":" not in target:
            raise LLMUpstreamError("invalid_model", "The checked Gemini target is invalid")
        return target.split(marker, 1)[1].split(":", 1)[0]

    async def complete(
        self, payload: PrivacyCheckedPayload | dict[str, Any]
    ) -> UpstreamResult:
        checked = self._checked(payload, stream=False)
        model = self._model_from_target(checked.target)
        url = f"{self.base_url}{checked.target}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            # Header form avoids putting the secret in URLs, access logs, or traces.
            headers["x-goog-api-key"] = self.api_key
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds, transport=self.transport
            ) as client:
                async with client.stream(
                    "POST", url, headers=headers, content=checked.body
                ) as response:
                    response_payload = await read_bounded_json(response, self.max_response_bytes)
                    status_code = response.status_code
        except LLMUpstreamError:
            raise
        except httpx.TimeoutException as exc:
            raise LLMUpstreamError(
                "upstream_timeout", "The upstream Gemini request timed out"
            ) from exc
        except httpx.HTTPError as exc:
            raise LLMUpstreamError(
                "upstream_unavailable", "The upstream Gemini service is unavailable"
            ) from exc

        if status_code >= 400:
            return UpstreamResult(status_code, response_payload)
        return UpstreamResult(status_code, self.from_gemini_response(response_payload, model))

    async def complete_stream(
        self, payload: PrivacyCheckedPayload | dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        checked = self._checked(payload, stream=True)
        model = self._model_from_target(checked.target)
        url = f"{self.base_url}{checked.target}"
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self.api_key:
            headers["x-goog-api-key"] = self.api_key
        stream_id = f"chatcmpl-gemini-{uuid.uuid4().hex[:16]}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds, transport=self.transport
            ) as client:
                async with client.stream(
                    "POST",
                    url,
                    headers=headers,
                    content=checked.body,
                ) as response:
                    if response.is_error:
                        raise LLMUpstreamError(
                            "upstream_error",
                            "The upstream Gemini service rejected the streaming request",
                        )
                    async for data in bounded_sse_data(response, self.max_response_bytes):
                        try:
                            chunk = json.loads(data.strip())
                        except json.JSONDecodeError as exc:
                            raise LLMUpstreamError(
                                "upstream_invalid_stream",
                                "The upstream Gemini service returned malformed SSE JSON",
                            ) from exc
                        if not isinstance(chunk, dict):
                            raise LLMUpstreamError(
                                "upstream_invalid_stream",
                                "The upstream Gemini service returned an invalid SSE event",
                            )
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
                                    "finish_reason": finish_reason.lower()
                                    if isinstance(finish_reason, str)
                                    else None,
                                }
                            ],
                        }
        except LLMUpstreamError:
            raise
        except httpx.TimeoutException as exc:
            raise LLMUpstreamError(
                "upstream_timeout", "The upstream Gemini stream timed out"
            ) from exc
        except httpx.HTTPError as exc:
            raise LLMUpstreamError(
                "upstream_unavailable", "The upstream Gemini stream is unavailable"
            ) from exc
