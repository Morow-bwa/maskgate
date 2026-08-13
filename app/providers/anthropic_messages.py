from __future__ import annotations

import json
from typing import Any

from app.privacy.ir import (
    CanonicalRequest,
    CanonicalRole,
    CanonicalStreamEvent,
    ErrorEvent,
    FinishEvent,
    RemoteToolDefinition,
    StructuredDataDelta,
    StructuredOutput,
    TextContent,
    TextDelta,
    ToolArgumentsDelta,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolResult,
    Turn,
    validated_json,
)

from .base import (
    AdapterPolicy,
    ProviderAdapterError,
    compact_json,
    emit_extensions,
    emit_remote_tool,
    expect_bool,
    expect_list,
    expect_object,
    expect_string,
    extensions_for_unknown_fields,
    remote_tool,
)
from .common import classification_for_role, generation_settings


class AnthropicMessagesAdapter:
    name = "anthropic-messages"
    version = "2026-08"

    def __init__(self, policy: AdapterPolicy | None = None) -> None:
        self.policy = policy or AdapterPolicy()

    def from_wire(self, payload: dict[str, Any]) -> CanonicalRequest:
        payload = expect_object(payload, self.name, "$")
        allowed = {
            "model",
            "max_tokens",
            "messages",
            "system",
            "tools",
            "tool_choice",
            "output_config",
            "stream",
            "temperature",
            "top_p",
            "stop_sequences",
        }
        extensions = extensions_for_unknown_fields(
            payload, allowed, provider=self.name, policy=self.policy
        )
        turns: list[Turn] = []
        if "system" in payload:
            turns.append(self._system_from_wire(payload["system"]))
        turns.extend(
            self._message_from_wire(item, index)
            for index, item in enumerate(
                expect_list(payload.get("messages"), self.name, "$.messages")
            )
        )
        return CanonicalRequest(
            model=expect_string(payload.get("model"), self.name, "$.model"),
            turns=tuple(turns),
            tools=tuple(
                self._tool_from_wire(item, index)
                for index, item in enumerate(
                    expect_list(payload.get("tools", []), self.name, "$.tools")
                )
            ),
            tool_choice=self._tool_choice_from_wire(payload.get("tool_choice")),
            structured_output=self._structured_output_from_wire(payload.get("output_config")),
            settings=generation_settings(
                provider=self.name,
                max_output_tokens=payload.get("max_tokens"),
                temperature=payload.get("temperature"),
                top_p=payload.get("top_p"),
                stop=payload.get("stop_sequences"),
            ),
            stream=expect_bool(payload.get("stream", False), self.name, "$.stream"),
            store=False,
            extensions=extensions,
        )

    def to_wire(self, request: CanonicalRequest) -> dict[str, Any]:
        if request.store:
            raise ProviderAdapterError(self.name, "$.store", "provider storage is unsupported")
        system: list[dict[str, str]] = []
        messages: list[dict[str, Any]] = []
        for index, turn in enumerate(request.turns):
            if turn.role in {CanonicalRole.SYSTEM, CanonicalRole.DEVELOPER}:
                if messages or any(not isinstance(item, TextContent) for item in turn.content):
                    raise ProviderAdapterError(
                        self.name, f"$.turns[{index}]", "system instructions must precede messages"
                    )
                system.extend(
                    {"type": "text", "text": item.text}
                    for item in turn.content
                    if isinstance(item, TextContent)
                )
            else:
                messages.append(self._message_to_wire(turn, index))
        if request.settings.max_output_tokens is None:
            raise ProviderAdapterError(
                self.name, "$.settings.max_output_tokens", "max_tokens is required"
            )
        payload: dict[str, Any] = {
            "model": request.model,
            "max_tokens": request.settings.max_output_tokens,
            "messages": messages,
            "stream": request.stream,
        }
        if system:
            payload["system"] = system
        if request.tools:
            payload["tools"] = [
                self._tool_to_wire(tool, index) for index, tool in enumerate(request.tools)
            ]
        if request.tool_choice is not None:
            payload["tool_choice"] = self._tool_choice_to_wire(request.tool_choice)
        if request.structured_output is not None:
            if request.structured_output.name != "response":
                raise ProviderAdapterError(
                    self.name, "$.structured_output.name", "Anthropic does not carry schema names"
                )
            payload["output_config"] = {
                "format": {
                    "type": "json_schema",
                    "schema": validated_json(request.structured_output.schema),
                }
            }
        settings = request.settings
        if settings.temperature is not None:
            payload["temperature"] = settings.temperature
        if settings.top_p is not None:
            payload["top_p"] = settings.top_p
        if settings.stop_sequences:
            payload["stop_sequences"] = list(settings.stop_sequences)
        emit_extensions(payload, request, provider=self.name, policy=self.policy)
        return payload

    def _system_from_wire(self, value: Any) -> Turn:
        if isinstance(value, str):
            texts = [value]
        else:
            texts = []
            for index, raw_block in enumerate(expect_list(value, self.name, "$.system")):
                path = f"$.system[{index}]"
                block = expect_object(raw_block, self.name, path)
                if set(block) != {"type", "text"} or block.get("type") != "text":
                    raise ProviderAdapterError(self.name, path, "unsupported system block")
                texts.append(expect_string(block.get("text"), self.name, f"{path}.text"))
        return Turn(
            CanonicalRole.SYSTEM,
            tuple(
                TextContent(text, classification_for_role(CanonicalRole.SYSTEM)) for text in texts
            ),
        )

    def _message_from_wire(self, value: Any, index: int) -> Turn:
        path = f"$.messages[{index}]"
        message = expect_object(value, self.name, path)
        if set(message) != {"role", "content"}:
            raise ProviderAdapterError(self.name, path, "unknown message field")
        role_value = expect_string(message.get("role"), self.name, f"{path}.role")
        if role_value not in {"user", "assistant"}:
            raise ProviderAdapterError(self.name, f"{path}.role", "unsupported role")
        role = CanonicalRole(role_value)
        raw_content = message.get("content")
        if isinstance(raw_content, str):
            return Turn(role, (TextContent(raw_content, classification_for_role(role)),))
        content: list[TextContent | ToolCall | ToolResult] = []
        for block_index, raw_block in enumerate(
            expect_list(raw_content, self.name, f"{path}.content")
        ):
            block_path = f"{path}.content[{block_index}]"
            block = expect_object(raw_block, self.name, block_path)
            block_type = expect_string(block.get("type"), self.name, f"{block_path}.type")
            if block_type == "text":
                if set(block) != {"type", "text"}:
                    raise ProviderAdapterError(self.name, block_path, "unknown text field")
                content.append(
                    TextContent(
                        expect_string(block.get("text"), self.name, f"{block_path}.text"),
                        classification_for_role(role),
                    )
                )
            elif block_type == "tool_use":
                if role is not CanonicalRole.ASSISTANT or set(block) != {
                    "type",
                    "id",
                    "name",
                    "input",
                }:
                    raise ProviderAdapterError(self.name, block_path, "invalid tool_use block")
                arguments = expect_object(block.get("input"), self.name, f"{block_path}.input")
                content.append(
                    ToolCall(
                        expect_string(block.get("id"), self.name, f"{block_path}.id"),
                        expect_string(block.get("name"), self.name, f"{block_path}.name"),
                        arguments,
                    )
                )
            elif block_type == "tool_result":
                allowed = {"type", "tool_use_id", "content", "is_error"}
                if role is not CanonicalRole.USER or set(block) - allowed:
                    raise ProviderAdapterError(self.name, block_path, "invalid tool_result block")
                content.append(
                    ToolResult(
                        expect_string(
                            block.get("tool_use_id"), self.name, f"{block_path}.tool_use_id"
                        ),
                        None,
                        self._result_from_wire(block.get("content"), f"{block_path}.content"),
                        expect_bool(
                            block.get("is_error", False), self.name, f"{block_path}.is_error"
                        ),
                    )
                )
            else:
                raise ProviderAdapterError(self.name, block_path, "unsupported content block")
        if len(content) == 1 and isinstance(content[0], ToolResult):
            return Turn(CanonicalRole.TOOL, tuple(content))
        if any(isinstance(item, ToolResult) for item in content):
            raise ProviderAdapterError(
                self.name, path, "tool results cannot share a canonical turn"
            )
        return Turn(role, tuple(content))

    def _message_to_wire(self, turn: Turn, index: int) -> dict[str, Any]:
        path = f"$.turns[{index}]"
        if turn.role is CanonicalRole.TOOL:
            if len(turn.content) != 1 or not isinstance(turn.content[0], ToolResult):
                raise ProviderAdapterError(self.name, path, "tool turn must contain one result")
            result = turn.content[0]
            block: dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": result.call_id,
                "content": compact_json(result.result),
            }
            if result.is_error:
                block["is_error"] = True
            return {"role": "user", "content": [block]}
        if turn.role not in {CanonicalRole.USER, CanonicalRole.ASSISTANT}:
            raise ProviderAdapterError(self.name, path, "unsupported message role")
        blocks: list[dict[str, Any]] = []
        for item in turn.content:
            if isinstance(item, TextContent):
                blocks.append({"type": "text", "text": item.text})
            elif isinstance(item, ToolCall) and turn.role is CanonicalRole.ASSISTANT:
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": item.call_id,
                        "name": item.name,
                        "input": validated_json(item.arguments),
                    }
                )
            else:
                raise ProviderAdapterError(self.name, path, "unsupported canonical content")
        return {"role": turn.role.value, "content": blocks}

    def _tool_from_wire(self, value: Any, index: int) -> ToolDefinition | RemoteToolDefinition:
        path = f"$.tools[{index}]"
        tool = expect_object(value, self.name, path)
        if "type" in tool:
            return remote_tool(
                provider=self.name,
                kind=str(tool.get("type")),
                configuration=tool,
                policy=self.policy,
                path=path,
            )
        allowed = {"name", "description", "input_schema", "strict"}
        if set(tool) - allowed:
            raise ProviderAdapterError(self.name, path, "unknown tool field")
        return ToolDefinition(
            expect_string(tool.get("name"), self.name, f"{path}.name"),
            expect_string(tool.get("description", ""), self.name, f"{path}.description"),
            expect_object(tool.get("input_schema"), self.name, f"{path}.input_schema"),
            expect_bool(tool.get("strict", False), self.name, f"{path}.strict"),
        )

    def _tool_to_wire(
        self, tool: ToolDefinition | RemoteToolDefinition, index: int
    ) -> dict[str, Any]:
        if isinstance(tool, RemoteToolDefinition):
            return emit_remote_tool(
                tool, provider=self.name, policy=self.policy, path=f"$.tools[{index}]"
            )
        return {
            "name": tool.name,
            "description": tool.description,
            "input_schema": validated_json(tool.input_schema),
            "strict": tool.strict,
        }

    def _tool_choice_from_wire(self, value: Any) -> ToolChoice | None:
        if value is None:
            return None
        choice = expect_object(value, self.name, "$.tool_choice")
        allowed = {"type", "name"}
        if set(choice) - allowed:
            raise ProviderAdapterError(self.name, "$.tool_choice", "unknown tool choice field")
        choice_type = expect_string(choice.get("type"), self.name, "$.tool_choice.type")
        mapping = {
            "auto": ToolChoiceMode.AUTO,
            "none": ToolChoiceMode.NONE,
            "any": ToolChoiceMode.REQUIRED,
        }
        if choice_type == "tool":
            return ToolChoice(
                ToolChoiceMode.SPECIFIC,
                expect_string(choice.get("name"), self.name, "$.tool_choice.name"),
            )
        if choice_type not in mapping or "name" in choice:
            raise ProviderAdapterError(self.name, "$.tool_choice", "unsupported tool choice")
        return ToolChoice(mapping[choice_type])

    @staticmethod
    def _tool_choice_to_wire(choice: ToolChoice) -> dict[str, Any]:
        if choice.mode is ToolChoiceMode.SPECIFIC:
            return {"type": "tool", "name": choice.name}
        mapping = {ToolChoiceMode.REQUIRED: "any"}
        return {"type": mapping.get(choice.mode, choice.mode.value)}

    def _structured_output_from_wire(self, value: Any) -> StructuredOutput | None:
        if value is None:
            return None
        output_config = expect_object(value, self.name, "$.output_config")
        if set(output_config) != {"format"}:
            raise ProviderAdapterError(self.name, "$.output_config", "unknown output config field")
        output = expect_object(output_config.get("format"), self.name, "$.output_config.format")
        if set(output) != {"type", "schema"} or output.get("type") != "json_schema":
            raise ProviderAdapterError(self.name, "$.output_config.format", "unsupported format")
        return StructuredOutput(
            "response",
            expect_object(output.get("schema"), self.name, "$.output_config.format.schema"),
            True,
        )

    def _result_from_wire(self, value: Any, path: str) -> Any:
        if isinstance(value, str):
            try:
                return validated_json(json.loads(value), path=path)
            except (json.JSONDecodeError, ValueError):
                return value
        blocks = expect_list(value, self.name, path)
        texts: list[str] = []
        for index, raw_block in enumerate(blocks):
            block_path = f"{path}[{index}]"
            block = expect_object(raw_block, self.name, block_path)
            if set(block) != {"type", "text"} or block.get("type") != "text":
                raise ProviderAdapterError(self.name, block_path, "unsupported tool result block")
            texts.append(expect_string(block.get("text"), self.name, f"{block_path}.text"))
        return "".join(texts)

    def parse_stream_event(
        self, event: dict[str, Any], *, structured_output: bool = False
    ) -> tuple[CanonicalStreamEvent, ...]:
        event = expect_object(event, self.name, "$event")
        event_type = expect_string(event.get("type"), self.name, "$event.type")
        if event_type == "content_block_delta":
            index = event.get("index", 0)
            delta = expect_object(event.get("delta"), self.name, "$event.delta")
            delta_type = expect_string(delta.get("type"), self.name, "$event.delta.type")
            if delta_type == "text_delta":
                path = ("content", index, "text")
                fragment = expect_string(delta.get("text"), self.name, "$event.delta.text")
                return (
                    StructuredDataDelta(path=path, fragment=fragment)
                    if structured_output
                    else TextDelta(path=path, text=fragment),
                )
            if delta_type == "input_json_delta":
                return (
                    ToolArgumentsDelta(
                        call_id=f"content-block-{index}",
                        path=("content", index, "input"),
                        fragment=expect_string(
                            delta.get("partial_json"), self.name, "$event.delta.partial_json"
                        ),
                    ),
                )
            raise ProviderAdapterError(self.name, "$event.delta.type", "unknown stream delta")
        if event_type == "message_delta":
            delta = expect_object(event.get("delta", {}), self.name, "$event.delta")
            reason = delta.get("stop_reason")
            return (FinishEvent(str(reason)),) if reason is not None else ()
        if event_type == "message_stop":
            return (FinishEvent("stop"),)
        if event_type == "error":
            error = expect_object(event.get("error", {}), self.name, "$event.error")
            return (
                ErrorEvent(
                    str(error.get("type", "provider_error")),
                    str(error.get("message", "provider error")),
                ),
            )
        if event_type in {"message_start", "content_block_start", "content_block_stop", "ping"}:
            return ()
        raise ProviderAdapterError(self.name, "$event.type", "unknown stream event")
