from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from app.masking.anonymizer import MappingItem, MaskingSession
from app.providers import ProviderAdapter, ProviderAdapterError
from app.providers.openai_chat import validate_chat_completion_response

from .output_guard import OutputPrivacyGuard
from .wire import (
    OPAQUE_TOKEN_PATTERN,
    FinalWirePrivacyGuard,
    PrivacyCheckedPayload,
    WirePrivacyViolation,
)


class PrivacyPipeline:
    """Deep Interface joining provider preparation, wire checks, and output policy."""

    def __init__(
        self,
        upstream: Any,
        provider_name: str,
        wire_guard: FinalWirePrivacyGuard,
        output_guard: OutputPrivacyGuard,
        *,
        ingress_adapter: ProviderAdapter | None = None,
        egress_adapter: ProviderAdapter | None = None,
    ) -> None:
        self.upstream = upstream
        self.provider_name = provider_name
        self.wire_guard = wire_guard
        self.output_guard = output_guard
        self.ingress_adapter = ingress_adapter
        self.egress_adapter = egress_adapter

    def prepare(
        self,
        payload: dict[str, Any],
        session: MaskingSession,
        allowlisted_values: list[str],
        *,
        stream: bool = False,
    ) -> PrivacyCheckedPayload:
        try:
            if self.ingress_adapter is not None and self.egress_adapter is not None:
                canonical = self.ingress_adapter.from_wire(payload)
                if canonical.stream is not stream:
                    raise ProviderAdapterError(
                        self.ingress_adapter.name,
                        "$.stream",
                        "request stream mode changed before provider serialization",
                    )
                wire_payload = self.egress_adapter.to_wire(canonical)
                provider = self.egress_adapter.name
                if hasattr(self.upstream, "prepare_request"):
                    _, target, _ = self.upstream.prepare_request(payload, stream=stream)
                else:
                    target = ""
            elif hasattr(self.upstream, "prepare_request"):
                provider, target, wire_payload = self.upstream.prepare_request(
                    payload,
                    stream=stream,
                )
            else:
                provider, target, wire_payload = self.provider_name or "custom", "", payload
        except ProviderAdapterError as exc:
            raise WirePrivacyViolation("provider adapter rejected the request") from exc
        replacements = {item.replacement for item in session.items}
        approved_tokens = {value for value in replacements if OPAQUE_TOKEN_PATTERN.fullmatch(value)}
        approved_values = (replacements - approved_tokens) | set(allowlisted_values)
        return self.wire_guard.check(
            provider=provider,
            target=target,
            payload=wire_payload,
            approved_tokens=approved_tokens,
            approved_values=approved_values,
        )

    async def complete(self, checked: PrivacyCheckedPayload) -> Any:
        argument = checked if self._accepts_checked_payload else checked.payload
        result = await self.upstream.complete(argument)
        if getattr(result, "status_code", 500) < 400:
            try:
                validate_chat_completion_response(getattr(result, "payload", None))
            except ProviderAdapterError as exc:
                raise ProviderOutputViolation from exc
        return result

    async def stream(self, checked: PrivacyCheckedPayload) -> AsyncIterator[dict[str, Any]]:
        argument = checked if self._accepts_checked_payload else checked.payload
        async for event in self.upstream.complete_stream(argument):
            try:
                # The current public streaming contract is OpenAI-compatible,
                # including events converted locally by the Gemini transport.
                if self.ingress_adapter is not None:
                    self.ingress_adapter.parse_stream_event(event)
            except ProviderAdapterError as exc:
                raise ProviderOutputViolation("upstream_invalid_stream") from exc
            yield event

    def process_output(self, payload: Any, mapping: list[MappingItem]) -> Any:
        return self.output_guard.process(payload, mapping)

    @property
    def _accepts_checked_payload(self) -> bool:
        return bool(getattr(self.upstream, "accepts_privacy_checked_payload", False))


class ProviderOutputViolation(ValueError):
    error_type = "upstream_invalid_response"
    message = "The upstream LLM returned an invalid response structure"

    def __init__(self, error_type: str = "upstream_invalid_response") -> None:
        self.error_type = error_type
        self.message = (
            "The upstream LLM returned an invalid stream structure"
            if error_type == "upstream_invalid_stream"
            else "The upstream LLM returned an invalid response structure"
        )
        super().__init__(self.message)
