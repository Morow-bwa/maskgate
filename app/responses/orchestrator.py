from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Any

from app.api import error_payload
from app.config import Settings
from app.identity import PrincipalContext
from app.masking.anonymizer import MaskingSession
from app.policies.policy_engine import PolicyBlocked, PolicyEngine
from app.privacy.approvals import ApprovalContext, ScopedApproval
from app.privacy.ir import (
    CanonicalRequest,
    StructuredContent,
    TextContent,
    ToolCall,
    ToolChoice,
    ToolDefinition,
    ToolResult,
    Turn,
)
from app.privacy.models import DetectionContext, PrivacyDirection, TokenScope
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.pipeline import ProviderOutputViolation
from app.privacy.runtime import PrivacyRequestContext, PrivacyRuntime
from app.privacy.wire import (
    OPAQUE_TOKEN_PATTERN,
    FinalWirePrivacyGuard,
    WirePrivacyViolation,
)
from app.providers import OpenAIResponsesAdapter, ProviderAdapterError
from app.providers.openai_responses import validate_openai_response
from app.proxy.llm_client import LLMUpstreamError, public_upstream_error


class UnsafeProtocolIdentifier(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ResponsesExecution:
    status_code: int
    payload: Any


class OpenAIResponsesOrchestrator:
    """Privacy-protected, stateless OpenAI Responses runtime."""

    def __init__(
        self,
        *,
        settings: Settings,
        upstream: Any,
        provider_ready: bool,
        adapter: OpenAIResponsesAdapter,
        privacy_runtime: PrivacyRuntime,
        policy: PolicyEngine,
        wire_guard: FinalWirePrivacyGuard,
        output_guard: OutputPrivacyGuard,
    ) -> None:
        self._settings = settings
        self._upstream = upstream
        self._provider_ready = provider_ready
        self._adapter = adapter
        self._privacy_runtime = privacy_runtime
        self._policy = policy
        self._wire_guard = wire_guard
        self._output_guard = output_guard

    async def execute(
        self, payload: dict[str, Any], principal: PrincipalContext
    ) -> ResponsesExecution:
        if not self._provider_ready:
            return self._error(
                503, "provider_not_configured", "The upstream provider is not configured"
            )

        session = MaskingSession(
            self._settings.masking_mode,
            self._policy,
            max_mappings=self._settings.conversation_max_mappings,
            max_sensitive_bytes=self._settings.conversation_max_sensitive_bytes,
        )
        approvals: list[ScopedApproval] = []
        try:
            canonical = self._adapter.from_wire(payload)
            if canonical.stream:
                return self._error(
                    422,
                    "unsupported_feature",
                    "Streaming is not supported on the privacy-protected Responses route",
                )
            transformed = self._transform_request(
                canonical,
                session=session,
                principal=principal,
                approvals=approvals,
            )
            wire_payload = self._adapter.to_wire(transformed)
            replacements = {item.replacement for item in session.items}
            approved_tokens = {
                value for value in replacements if OPAQUE_TOKEN_PATTERN.fullmatch(value)
            }
            now_epoch = time.time()
            approval_context = ApprovalContext(
                principal_id=principal.vault_namespace,
                application_id=principal.application_id,
                route="/v1/responses",
                provider=self._adapter.name,
                direction=PrivacyDirection.INPUT,
                purpose=self._settings.default_purpose,
                policy_revision=self._privacy_runtime.policy_revision,
                now_epoch=now_epoch,
            )
            if any(not approval.scope_matches(approval_context) for approval in approvals):
                raise WirePrivacyViolation("scoped approval does not match the active operation")
            wire_approvals = tuple(
                self._bind_response_approval(approval, wire_payload)
                for approval in approvals
            )
            checked = self._wire_guard.check(
                provider=self._adapter.name,
                target="/responses",
                payload=wire_payload,
                approved_tokens=approved_tokens,
                approved_values=replacements - approved_tokens,
                scoped_approvals=wire_approvals,
                approval_context=approval_context,
            )
        except ProviderAdapterError:
            return self._error(
                422, "invalid_request", "The Responses request is unsupported or invalid"
            )
        except UnsafeProtocolIdentifier:
            return self._error(
                400,
                "privacy_policy_block",
                "A provider protocol identifier contains sensitive data",
            )
        except WirePrivacyViolation:
            return self._error(
                400,
                "wire_privacy_violation",
                "Final wire privacy validation rejected the provider request",
            )
        except PolicyBlocked:
            return self._error(400, "privacy_policy_block", "Sensitive data was blocked by policy")

        try:
            result = await self._upstream.complete(checked)
            if result.status_code >= 400:
                return self._error(
                    502,
                    "upstream_provider_error",
                    "The upstream provider rejected the request",
                )
            safe_response = validate_openai_response(result.payload)
            return ResponsesExecution(
                result.status_code,
                self._output_guard.process(safe_response, session.items),
            )
        except LLMUpstreamError as exc:
            error_type, message = public_upstream_error(exc.error_type)
            return self._error(502, error_type, message)
        except (ProviderAdapterError, ProviderOutputViolation, ValueError):
            return self._error(
                502,
                "upstream_invalid_response",
                "The upstream LLM returned an invalid response structure",
            )

    def _transform_request(
        self,
        request: CanonicalRequest,
        *,
        session: MaskingSession,
        principal: PrincipalContext,
        approvals: list[ScopedApproval],
    ) -> CanonicalRequest:
        privacy_request = PrivacyRequestContext(
            route="/v1/responses",
            provider=self._adapter.name,
            model=request.model,
            jurisdiction=self._settings.jurisdiction,
            purpose=self._settings.default_purpose,
            token_scope=TokenScope.REQUEST,
            policy_revision=self._privacy_runtime.policy_revision,
        )

        def transform_text(
            text: str,
            path: tuple[str | int, ...],
            role: str | None,
        ) -> str:
            result = self._privacy_runtime.transform_text(
                text,
                session=session,
                principal=principal,
                request=privacy_request,
                json_path=path,
                role=role,
            )
            approvals.extend(result.approvals)
            return result.text

        def identifier(text: str, path: tuple[str | int, ...]) -> str:
            transformed = transform_text(text, path, "protocol_identifier")
            if transformed != text:
                raise UnsafeProtocolIdentifier
            return text

        def structured(value: Any, path: tuple[str | int, ...], role: str) -> Any:
            if isinstance(value, str):
                return transform_text(value, path, role)
            if isinstance(value, list):
                return [structured(item, (*path, index), role) for index, item in enumerate(value)]
            if isinstance(value, dict):
                transformed: dict[str, Any] = {}
                for key, item in value.items():
                    updated_key = transform_text(key, (*path, "<key>"), role)
                    if updated_key in transformed:
                        raise UnsafeProtocolIdentifier
                    transformed[updated_key] = structured(item, (*path, key), role)
                return transformed
            return value

        turns: list[Turn] = []
        for turn_index, turn in enumerate(request.turns):
            content: list[Any] = []
            for content_index, item in enumerate(turn.content):
                path = ("turns", turn_index, "content", content_index)
                if isinstance(item, TextContent):
                    content.append(
                        replace(
                            item,
                            text=transform_text(
                                item.text, (*path, "text"), item.classification.value
                            ),
                        )
                    )
                elif isinstance(item, StructuredContent):
                    content.append(
                        replace(
                            item,
                            value=structured(
                                item.value, (*path, "value"), item.classification.value
                            ),
                        )
                    )
                elif isinstance(item, ToolCall):
                    content.append(
                        replace(
                            item,
                            call_id=identifier(item.call_id, (*path, "call_id")),
                            name=identifier(item.name, (*path, "name")),
                            arguments=structured(
                                item.arguments, (*path, "arguments"), "tool_argument"
                            ),
                        )
                    )
                elif isinstance(item, ToolResult):
                    content.append(
                        replace(
                            item,
                            call_id=identifier(item.call_id, (*path, "call_id")),
                            name=(identifier(item.name, (*path, "name")) if item.name else None),
                            result=structured(item.result, (*path, "result"), "tool_result"),
                        )
                    )
                else:  # pragma: no cover - CanonicalContent is a closed union
                    raise ProviderAdapterError(self._adapter.name, "$", "unsupported content")
            turns.append(replace(turn, content=tuple(content)))

        tools = []
        for index, tool in enumerate(request.tools):
            if not isinstance(tool, ToolDefinition):
                raise ProviderAdapterError(self._adapter.name, f"$.tools[{index}]", "remote tool")
            tools.append(
                replace(
                    tool,
                    name=identifier(tool.name, ("tools", index, "name")),
                    description=transform_text(
                        tool.description, ("tools", index, "description"), "tool_description"
                    ),
                    input_schema=structured(
                        tool.input_schema, ("tools", index, "parameters"), "tool_schema"
                    ),
                )
            )

        structured_output = request.structured_output
        if structured_output is not None:
            structured_output = replace(
                structured_output,
                name=identifier(structured_output.name, ("text", "format", "name")),
                schema=structured(
                    structured_output.schema,
                    ("text", "format", "schema"),
                    "structured_output_schema",
                ),
            )
        tool_choice: ToolChoice | None = request.tool_choice
        if tool_choice is not None and tool_choice.name is not None:
            tool_choice = replace(
                tool_choice,
                name=identifier(tool_choice.name, ("tool_choice", "name")),
            )
        return replace(
            request,
            model=identifier(request.model, ("model",)),
            turns=tuple(turns),
            tools=tuple(tools),
            structured_output=structured_output,
            tool_choice=tool_choice,
            stream=False,
            store=False,
        )

    def _bind_response_approval(
        self,
        approval: ScopedApproval,
        payload: dict[str, Any],
    ) -> ScopedApproval:
        candidates: list[tuple[str | int, ...]] = []

        def inspect(value: Any, path: tuple[str | int, ...]) -> None:
            if isinstance(value, str):
                if not self._response_path_preserves(approval.source_path, path):
                    return
                detections = self._privacy_runtime.detector.analyze(
                    value,
                    DetectionContext(
                        profile=self._privacy_runtime.detector.profile,
                        json_path=path,
                        direction=PrivacyDirection.INPUT,
                    ),
                )
                if any(
                    approval.matches_value(
                        value[detection.start : detection.end],
                        detection.entity_type,
                    )
                    for detection in detections
                ):
                    candidates.append(path)
                return
            if isinstance(value, list):
                for index, item in enumerate(value):
                    inspect(item, (*path, index))
                return
            if isinstance(value, dict):
                for key, item in value.items():
                    inspect(item, (*path, key))

        inspect(payload, ())
        if len(candidates) != 1:
            raise WirePrivacyViolation(
                "Responses serialization cannot preserve scoped approval provenance"
            )
        return approval.bind_to_wire(
            provider=self._adapter.name,
            wire_path=candidates[0],
        )

    @staticmethod
    def _response_path_preserves(
        source: tuple[str | int, ...],
        wire: tuple[str | int, ...],
    ) -> bool:
        if source and source[0] == "turns" and source[-1:] == ("text",):
            return wire == ("instructions",) or (
                len(wire) >= 5
                and wire[0] == "input"
                and wire[-3] == "content"
                and wire[-1] == "text"
            )
        if len(source) >= 3 and source[:1] == ("tools",):
            return wire == source
        if source[:2] == ("text", "format"):
            return wire == source
        return False

    @staticmethod
    def _error(status_code: int, error_type: str, message: str) -> ResponsesExecution:
        return ResponsesExecution(status_code, error_payload(message, error_type))
