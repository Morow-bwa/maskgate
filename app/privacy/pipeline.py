from __future__ import annotations

import time
from collections.abc import AsyncIterator
from typing import Any

from app.identity import PrincipalContext
from app.masking.anonymizer import MappingItem, MaskingSession
from app.observability import PrivacyMetric, PrivacyMetrics, PrivacyStage
from app.privacy.approvals import ApprovalContext, ScopedApproval
from app.privacy.models import PrivacyDirection
from app.privacy.runtime import PrivacyRequestContext
from app.providers import ProviderAdapter, ProviderAdapterError
from app.providers.openai_chat import validate_chat_completion_response
from app.proxy.contracts import TransportCapabilities

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
        transport_capabilities: TransportCapabilities | None = None,
        metrics: PrivacyMetrics | None = None,
    ) -> None:
        self.upstream = upstream
        self.provider_name = provider_name
        self.wire_guard = wire_guard
        self.output_guard = output_guard
        self.ingress_adapter = ingress_adapter
        self.egress_adapter = egress_adapter
        self.transport_capabilities = transport_capabilities or TransportCapabilities(
            accepts_checked_payload=bool(
                getattr(upstream, "accepts_privacy_checked_payload", False)
            ),
            supports_streaming=callable(getattr(upstream, "complete_stream", None)),
        )
        self.metrics = metrics

    def prepare(
        self,
        payload: dict[str, Any],
        session: MaskingSession,
        approvals: list[ScopedApproval],
        *,
        principal: PrincipalContext | None = None,
        request_context: PrivacyRequestContext | None = None,
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
        approved_values = replacements - approved_tokens
        now_epoch = time.time()
        wire_approvals: tuple[ScopedApproval, ...] = ()
        wire_context: ApprovalContext | None = None
        if approvals:
            if principal is None or request_context is None:
                raise WirePrivacyViolation(
                    "scoped approvals require trusted operation context"
                )
            source_context = ApprovalContext(
                principal_id=principal.vault_namespace,
                application_id=principal.application_id,
                route=request_context.route,
                provider=request_context.provider,
                direction=PrivacyDirection.INPUT,
                purpose=request_context.purpose,
                policy_revision=request_context.policy_revision,
                now_epoch=now_epoch,
            )
            if any(not approval.scope_matches(source_context) for approval in approvals):
                raise WirePrivacyViolation("scoped approval does not match the active operation")
            if provider != "openai-chat-completions":
                raise WirePrivacyViolation(
                    "provider translation cannot preserve scoped approval provenance"
                )
            wire_approvals = tuple(
                approval.bind_to_wire(provider=provider, wire_path=approval.source_path)
                for approval in approvals
            )
            wire_context = ApprovalContext(
                principal_id=principal.vault_namespace,
                application_id=principal.application_id,
                route=request_context.route,
                provider=provider,
                direction=PrivacyDirection.INPUT,
                purpose=request_context.purpose,
                policy_revision=request_context.policy_revision,
                now_epoch=now_epoch,
            )
        started = time.perf_counter()
        try:
            return self.wire_guard.check(
                provider=provider,
                target=target,
                payload=wire_payload,
                approved_tokens=approved_tokens,
                approved_values=approved_values,
                scoped_approvals=wire_approvals,
                approval_context=wire_context,
            )
        except WirePrivacyViolation:
            if self.metrics is not None:
                self.metrics.increment(PrivacyMetric.WIRE_REJECTIONS)
            raise
        finally:
            if self.metrics is not None:
                self.metrics.observe(PrivacyStage.WIRE_GUARD, time.perf_counter() - started)

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
        started = time.perf_counter()
        try:
            return self.output_guard.process(payload, mapping)
        except (ValueError, RecursionError) as exc:
            if self.metrics is not None:
                self.metrics.increment(PrivacyMetric.OUTPUT_FAILURES)
            raise ProviderOutputViolation from exc
        finally:
            if self.metrics is not None:
                self.metrics.observe(PrivacyStage.OUTPUT_GUARD, time.perf_counter() - started)

    @property
    def _accepts_checked_payload(self) -> bool:
        return self.transport_capabilities.accepts_checked_payload


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
