from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from app.chat.orchestrator import error_payload
from app.config import Settings
from app.identity import PrincipalContext
from app.masking.anonymizer import MaskingSession
from app.policies.policy_engine import PolicyBlocked, PolicyEngine
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
from app.privacy.models import TokenScope
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
        allowlisted_values: list[str] = []
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
                allowlisted_values=allowlisted_values,
            )
            wire_payload = self._adapter.to_wire(transformed)
            replacements = {item.replacement for item in session.items}
            approved_tokens = {
                value for value in replacements if OPAQUE_TOKEN_PATTERN.fullmatch(value)
            }
            checked = self._wire_guard.check(
                provider=self._adapter.name,
                target="/responses",
                payload=wire_payload,
                approved_tokens=approved_tokens,
                approved_values=(replacements - approved_tokens) | set(allowlisted_values),
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
        except PolicyBlocked:
            return self._error(400, "privacy_policy_block", "Sensitive data was blocked by policy")
        except WirePrivacyViolation:
            return self._error(
                400,
                "wire_privacy_violation",
                "Final wire privacy validation rejected the provider request",
            )

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
        allowlisted_values: list[str],
    ) -> CanonicalRequest:
        privacy_request = PrivacyRequestContext(
            route="/v1/responses",
            provider=self._adapter.name,
            model=request.model,
            jurisdiction=self._settings.jurisdiction,
            purpose=self._settings.default_purpose,
            token_scope=TokenScope.REQUEST,
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
            allowlisted_values.extend(result.approved_originals)
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

    @staticmethod
    def _error(status_code: int, error_type: str, message: str) -> ResponsesExecution:
        return ResponsesExecution(status_code, error_payload(message, error_type))
