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
    enforce_storage,
    expect_bool,
    expect_list,
    expect_object,
    expect_string,
    extensions_for_unknown_fields,
    read_json_text,
    remote_tool,
)
from .common import classification_for_role, generation_settings, parse_simple_tool_choice


class OpenAIResponsesAdapter:
    name = "openai-responses"
    version = "2026-08"

    def __init__(self, policy: AdapterPolicy | None = None) -> None:
        self.policy = policy or AdapterPolicy()

    def from_wire(self, payload: dict[str, Any]) -> CanonicalRequest:
        payload = expect_object(payload, self.name, "$")
        allowed = {
            "model",
            "input",
            "instructions",
            "tools",
            "tool_choice",
            "text",
            "stream",
            "store",
            "max_output_tokens",
            "temperature",
            "top_p",
        }
        extensions = extensions_for_unknown_fields(
            payload, allowed, provider=self.name, policy=self.policy
        )
        turns: list[Turn] = []
        if "instructions" in payload:
            turns.append(
                Turn(
                    CanonicalRole.SYSTEM,
                    (
                        TextContent(
                            expect_string(payload["instructions"], self.name, "$.instructions"),
                            classification_for_role(CanonicalRole.SYSTEM),
                        ),
                    ),
                )
            )
        turns.extend(self._input_from_wire(payload.get("input")))
        tools = tuple(
            self._tool_from_wire(item, index)
            for index, item in enumerate(
                expect_list(payload.get("tools", []), self.name, "$.tools")
            )
        )
        return CanonicalRequest(
            model=expect_string(payload.get("model"), self.name, "$.model"),
            turns=tuple(turns),
            tools=tools,
            tool_choice=self._tool_choice_from_wire(payload.get("tool_choice")),
            structured_output=self._structured_output_from_wire(payload.get("text")),
            settings=generation_settings(
                provider=self.name,
                max_output_tokens=payload.get("max_output_tokens"),
                temperature=payload.get("temperature"),
                top_p=payload.get("top_p"),
            ),
            stream=expect_bool(payload.get("stream", False), self.name, "$.stream"),
            store=enforce_storage(payload.get("store"), self.name, self.policy, "$.store"),
            extensions=extensions,
        )

    def to_wire(self, request: CanonicalRequest) -> dict[str, Any]:
        if request.store and not self.policy.allow_provider_storage:
            raise ProviderAdapterError(self.name, "$.store", "provider storage is disabled")
        instructions: list[str] = []
        input_items: list[dict[str, Any]] = []
        for index, turn in enumerate(request.turns):
            if turn.role in {CanonicalRole.SYSTEM, CanonicalRole.DEVELOPER}:
                if instructions or any(not isinstance(item, TextContent) for item in turn.content):
                    raise ProviderAdapterError(
                        self.name,
                        f"$.turns[{index}]",
                        "Responses supports one text instruction turn",
                    )
                instructions.append(
                    "\n".join(item.text for item in turn.content if isinstance(item, TextContent))
                )
                continue
            input_items.extend(self._turn_to_items(turn, index))
        payload: dict[str, Any] = {
            "model": request.model,
            "input": input_items,
            "stream": request.stream,
            "store": request.store,
        }
        if instructions:
            payload["instructions"] = instructions[0]
        if request.tools:
            payload["tools"] = [
                self._tool_to_wire(tool, index) for index, tool in enumerate(request.tools)
            ]
        if request.tool_choice is not None:
            payload["tool_choice"] = self._tool_choice_to_wire(request.tool_choice)
        if request.structured_output is not None:
            output = request.structured_output
            payload["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": output.name,
                    "strict": output.strict,
                    "schema": validated_json(output.schema),
                }
            }
        settings = request.settings
        if settings.max_output_tokens is not None:
            payload["max_output_tokens"] = settings.max_output_tokens
        if settings.temperature is not None:
            payload["temperature"] = settings.temperature
        if settings.top_p is not None:
            payload["top_p"] = settings.top_p
        if settings.stop_sequences:
            raise ProviderAdapterError(self.name, "$.settings.stop_sequences", "not supported")
        emit_extensions(payload, request, provider=self.name, policy=self.policy)
        return payload

    def _input_from_wire(self, value: Any) -> list[Turn]:
        if isinstance(value, str):
            return [
                Turn(
                    CanonicalRole.USER,
                    (TextContent(value, classification_for_role(CanonicalRole.USER)),),
                )
            ]
        turns: list[Turn] = []
        for index, raw_item in enumerate(expect_list(value, self.name, "$.input")):
            path = f"$.input[{index}]"
            item = expect_object(raw_item, self.name, path)
            item_type = expect_string(item.get("type"), self.name, f"{path}.type")
            if item_type == "message":
                turns.append(self._message_item(item, path))
            elif item_type == "function_call":
                if set(item) != {"type", "call_id", "name", "arguments"}:
                    raise ProviderAdapterError(self.name, path, "unknown function call field")
                arguments = read_json_text(item.get("arguments"), self.name, f"{path}.arguments")
                if not isinstance(arguments, dict):
                    raise ProviderAdapterError(
                        self.name, f"{path}.arguments", "expected object JSON"
                    )
                turns.append(
                    Turn(
                        CanonicalRole.ASSISTANT,
                        (
                            ToolCall(
                                expect_string(item.get("call_id"), self.name, f"{path}.call_id"),
                                expect_string(item.get("name"), self.name, f"{path}.name"),
                                arguments,
                            ),
                        ),
                    )
                )
            elif item_type == "function_call_output":
                if set(item) != {"type", "call_id", "output"}:
                    raise ProviderAdapterError(self.name, path, "unknown function output field")
                turns.append(
                    Turn(
                        CanonicalRole.TOOL,
                        (
                            ToolResult(
                                expect_string(item.get("call_id"), self.name, f"{path}.call_id"),
                                None,
                                self._json_or_text(item.get("output"), f"{path}.output"),
                            ),
                        ),
                    )
                )
            else:
                raise ProviderAdapterError(self.name, path, "unsupported input item")
        return turns

    def _message_item(self, item: dict[str, Any], path: str) -> Turn:
        if set(item) != {"type", "role", "content"}:
            raise ProviderAdapterError(self.name, path, "unknown message item field")
        role_value = expect_string(item.get("role"), self.name, f"{path}.role")
        try:
            role = CanonicalRole(role_value)
        except ValueError as exc:
            raise ProviderAdapterError(self.name, f"{path}.role", "unsupported role") from exc
        if role is CanonicalRole.TOOL:
            raise ProviderAdapterError(
                self.name, f"{path}.role", "tool results need function_call_output"
            )
        blocks: list[TextContent] = []
        raw_content = item.get("content")
        if isinstance(raw_content, str):
            blocks.append(TextContent(raw_content, classification_for_role(role)))
        else:
            for block_index, raw_block in enumerate(
                expect_list(raw_content, self.name, f"{path}.content")
            ):
                block_path = f"{path}.content[{block_index}]"
                block = expect_object(raw_block, self.name, block_path)
                expected_type = "output_text" if role is CanonicalRole.ASSISTANT else "input_text"
                if set(block) != {"type", "text"} or block.get("type") != expected_type:
                    raise ProviderAdapterError(self.name, block_path, "unsupported content block")
                blocks.append(
                    TextContent(
                        expect_string(block.get("text"), self.name, f"{block_path}.text"),
                        classification_for_role(role),
                    )
                )
        return Turn(role, tuple(blocks))

    def _turn_to_items(self, turn: Turn, index: int) -> list[dict[str, Any]]:
        path = f"$.turns[{index}]"
        if turn.role is CanonicalRole.TOOL:
            if len(turn.content) != 1 or not isinstance(turn.content[0], ToolResult):
                raise ProviderAdapterError(self.name, path, "tool turn must contain one result")
            result = turn.content[0]
            return [
                {
                    "type": "function_call_output",
                    "call_id": result.call_id,
                    "output": compact_json(result.result),
                }
            ]
        items: list[dict[str, Any]] = []
        texts = [item for item in turn.content if isinstance(item, TextContent)]
        calls = [item for item in turn.content if isinstance(item, ToolCall)]
        if len(texts) + len(calls) != len(turn.content):
            raise ProviderAdapterError(self.name, path, "unsupported canonical content")
        if texts:
            content_type = "output_text" if turn.role is CanonicalRole.ASSISTANT else "input_text"
            items.append(
                {
                    "type": "message",
                    "role": turn.role.value,
                    "content": [{"type": content_type, "text": item.text} for item in texts],
                }
            )
        for call in calls:
            if turn.role is not CanonicalRole.ASSISTANT:
                raise ProviderAdapterError(self.name, path, "tool calls require assistant role")
            items.append(
                {
                    "type": "function_call",
                    "call_id": call.call_id,
                    "name": call.name,
                    "arguments": compact_json(call.arguments),
                }
            )
        return items

    def _tool_from_wire(self, value: Any, index: int) -> ToolDefinition | RemoteToolDefinition:
        path = f"$.tools[{index}]"
        tool = expect_object(value, self.name, path)
        if tool.get("type") != "function":
            return remote_tool(
                provider=self.name,
                kind=str(tool.get("type", "unknown")),
                configuration=tool,
                policy=self.policy,
                path=path,
            )
        allowed = {"type", "name", "description", "parameters", "strict"}
        if set(tool) - allowed:
            raise ProviderAdapterError(self.name, path, "unknown function tool field")
        return ToolDefinition(
            name=expect_string(tool.get("name"), self.name, f"{path}.name"),
            description=expect_string(
                tool.get("description", ""), self.name, f"{path}.description"
            ),
            input_schema=expect_object(tool.get("parameters"), self.name, f"{path}.parameters"),
            strict=expect_bool(tool.get("strict", True), self.name, f"{path}.strict"),
        )

    def _tool_to_wire(
        self, tool: ToolDefinition | RemoteToolDefinition, index: int
    ) -> dict[str, Any]:
        if isinstance(tool, RemoteToolDefinition):
            return emit_remote_tool(
                tool, provider=self.name, policy=self.policy, path=f"$.tools[{index}]"
            )
        return {
            "type": "function",
            "name": tool.name,
            "description": tool.description,
            "parameters": validated_json(tool.input_schema),
            "strict": tool.strict,
        }

    def _tool_choice_from_wire(self, value: Any) -> ToolChoice | None:
        if value is None or isinstance(value, str):
            return parse_simple_tool_choice(value, self.name, "$.tool_choice")
        choice = expect_object(value, self.name, "$.tool_choice")
        if set(choice) != {"type", "name"} or choice.get("type") != "function":
            raise ProviderAdapterError(self.name, "$.tool_choice", "unsupported tool choice")
        return ToolChoice(
            ToolChoiceMode.SPECIFIC,
            expect_string(choice.get("name"), self.name, "$.tool_choice.name"),
        )

    @staticmethod
    def _tool_choice_to_wire(choice: ToolChoice) -> Any:
        if choice.mode is ToolChoiceMode.SPECIFIC:
            return {"type": "function", "name": choice.name}
        return choice.mode.value

    def _structured_output_from_wire(self, value: Any) -> StructuredOutput | None:
        if value is None:
            return None
        text = expect_object(value, self.name, "$.text")
        if set(text) != {"format"}:
            raise ProviderAdapterError(self.name, "$.text", "unknown text config field")
        output = expect_object(text.get("format"), self.name, "$.text.format")
        if (
            set(output) != {"type", "name", "strict", "schema"}
            or output.get("type") != "json_schema"
        ):
            raise ProviderAdapterError(self.name, "$.text.format", "unsupported response format")
        return StructuredOutput(
            expect_string(output.get("name"), self.name, "$.text.format.name"),
            expect_object(output.get("schema"), self.name, "$.text.format.schema"),
            expect_bool(output.get("strict"), self.name, "$.text.format.strict"),
        )

    def _json_or_text(self, value: Any, path: str) -> Any:
        text = expect_string(value, self.name, path)
        try:
            return validated_json(json.loads(text), path=path)
        except (json.JSONDecodeError, ValueError):
            return text

    def parse_stream_event(
        self, event: dict[str, Any], *, structured_output: bool = False
    ) -> tuple[CanonicalStreamEvent, ...]:
        event = expect_object(event, self.name, "$event")
        event_type = expect_string(event.get("type"), self.name, "$event.type")
        if event_type == "response.output_text.delta":
            path = (
                "output",
                event.get("output_index", 0),
                "content",
                event.get("content_index", 0),
            )
            fragment = expect_string(event.get("delta"), self.name, "$event.delta")
            if structured_output:
                return (StructuredDataDelta(path=path, fragment=fragment),)
            return (TextDelta(path=path, text=fragment),)
        if event_type == "response.function_call_arguments.delta":
            return (
                ToolArgumentsDelta(
                    call_id=str(event.get("item_id") or event.get("call_id") or "unknown"),
                    path=("output", event.get("output_index", 0), "arguments"),
                    fragment=expect_string(event.get("delta"), self.name, "$event.delta"),
                ),
            )
        if event_type == "response.completed":
            return (FinishEvent("completed"),)
        if event_type in {"error", "response.failed", "response.incomplete"}:
            error = expect_object(event.get("error", {}), self.name, "$event.error")
            return (
                ErrorEvent(
                    str(error.get("code", event_type)), str(error.get("message", event_type))
                ),
            )
        if event_type in {
            "response.created",
            "response.in_progress",
            "response.output_item.added",
            "response.output_item.done",
            "response.content_part.added",
            "response.content_part.done",
            "response.output_text.done",
            "response.function_call_arguments.done",
        }:
            return ()
        raise ProviderAdapterError(self.name, "$event.type", "unknown stream event")
