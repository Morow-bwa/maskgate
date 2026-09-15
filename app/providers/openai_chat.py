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
from .common import classification_for_role, generation_settings


class OpenAIChatCompletionsAdapter:
    name = "openai-chat-completions"
    version = "2026-08"

    def __init__(self, policy: AdapterPolicy | None = None) -> None:
        self.policy = policy or AdapterPolicy()

    def from_wire(self, payload: dict[str, Any]) -> CanonicalRequest:
        payload = expect_object(payload, self.name, "$")
        allowed = {
            "model",
            "messages",
            "tools",
            "tool_choice",
            "response_format",
            "stream",
            "store",
            "temperature",
            "top_p",
            "max_tokens",
            "max_completion_tokens",
            "stop",
        }
        extensions = extensions_for_unknown_fields(
            payload, allowed, provider=self.name, policy=self.policy
        )
        model = expect_string(payload.get("model"), self.name, "$.model")
        turns = tuple(
            self._message_from_wire(item, index)
            for index, item in enumerate(
                expect_list(payload.get("messages"), self.name, "$.messages")
            )
        )
        tools = tuple(
            self._tool_from_wire(item, index)
            for index, item in enumerate(
                expect_list(payload.get("tools", []), self.name, "$.tools")
            )
        )
        max_tokens = payload.get("max_completion_tokens", payload.get("max_tokens"))
        if "max_completion_tokens" in payload and "max_tokens" in payload:
            raise ProviderAdapterError(
                self.name, "$.max_tokens", "two maximum-token fields are ambiguous"
            )
        return CanonicalRequest(
            model=model,
            turns=turns,
            tools=tools,
            tool_choice=self._tool_choice_from_wire(payload.get("tool_choice")),
            structured_output=self._structured_output_from_wire(payload.get("response_format")),
            settings=generation_settings(
                provider=self.name,
                max_output_tokens=max_tokens,
                temperature=payload.get("temperature"),
                top_p=payload.get("top_p"),
                stop=payload.get("stop"),
            ),
            stream=expect_bool(payload.get("stream", False), self.name, "$.stream"),
            store=enforce_storage(payload.get("store"), self.name, self.policy, "$.store"),
            extensions=extensions,
        )

    def to_wire(self, request: CanonicalRequest) -> dict[str, Any]:
        if request.store and not self.policy.allow_provider_storage:
            raise ProviderAdapterError(self.name, "$.store", "provider storage is disabled")
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": [
                self._message_to_wire(turn, index) for index, turn in enumerate(request.turns)
            ],
            "stream": request.stream,
            "store": request.store,
        }
        if request.tools:
            payload["tools"] = [
                self._tool_to_wire(tool, index) for index, tool in enumerate(request.tools)
            ]
        if request.tool_choice is not None:
            payload["tool_choice"] = self._tool_choice_to_wire(request.tool_choice)
        if request.structured_output is not None:
            output = request.structured_output
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": output.name,
                    "strict": output.strict,
                    "schema": validated_json(output.schema),
                },
            }
        settings = request.settings
        if settings.max_output_tokens is not None:
            payload["max_completion_tokens"] = settings.max_output_tokens
        if settings.temperature is not None:
            payload["temperature"] = settings.temperature
        if settings.top_p is not None:
            payload["top_p"] = settings.top_p
        if settings.stop_sequences:
            payload["stop"] = list(settings.stop_sequences)
        emit_extensions(payload, request, provider=self.name, policy=self.policy)
        return payload

    def _message_from_wire(self, value: Any, index: int) -> Turn:
        path = f"$.messages[{index}]"
        message = expect_object(value, self.name, path)
        allowed = {"role", "content", "name", "tool_calls", "tool_call_id"}
        unknown = set(message) - allowed
        if unknown:
            field = sorted(unknown)[0]
            raise ProviderAdapterError(self.name, f"{path}.{field}", "unknown message field")
        role_value = expect_string(message.get("role"), self.name, f"{path}.role")
        try:
            role = CanonicalRole(role_value)
        except ValueError as exc:
            raise ProviderAdapterError(self.name, f"{path}.role", "unsupported role") from exc
        name = message.get("name")
        if name is not None:
            name = expect_string(name, self.name, f"{path}.name")

        if role is CanonicalRole.TOOL:
            if "tool_calls" in message:
                raise ProviderAdapterError(
                    self.name, path, "tool messages cannot contain tool_calls"
                )
            call_id = expect_string(message.get("tool_call_id"), self.name, f"{path}.tool_call_id")
            result = self._json_or_text(message.get("content"), f"{path}.content")
            return Turn(role=role, content=(ToolResult(call_id, name, result),), name=name)

        if "tool_call_id" in message:
            raise ProviderAdapterError(
                self.name, f"{path}.tool_call_id", "field requires tool role"
            )
        content: list[TextContent | ToolCall] = []
        raw_content = message.get("content")
        if raw_content is not None:
            content.extend(self._text_blocks(raw_content, role, f"{path}.content"))
        for tool_index, item in enumerate(
            expect_list(message.get("tool_calls", []), self.name, f"{path}.tool_calls")
        ):
            if role is not CanonicalRole.ASSISTANT:
                raise ProviderAdapterError(
                    self.name, f"{path}.tool_calls", "field requires assistant role"
                )
            content.append(self._tool_call_from_wire(item, f"{path}.tool_calls[{tool_index}]"))
        if not content:
            raise ProviderAdapterError(self.name, path, "message has no supported content")
        return Turn(role=role, content=tuple(content), name=name)

    def _text_blocks(self, value: Any, role: CanonicalRole, path: str) -> list[TextContent]:
        classification = classification_for_role(role)
        if isinstance(value, str):
            return [TextContent(value, classification)]
        blocks: list[TextContent] = []
        for index, item in enumerate(expect_list(value, self.name, path)):
            block_path = f"{path}[{index}]"
            block = expect_object(item, self.name, block_path)
            if set(block) != {"type", "text"} or block.get("type") != "text":
                raise ProviderAdapterError(self.name, block_path, "unsupported content block")
            blocks.append(
                TextContent(
                    expect_string(block.get("text"), self.name, f"{block_path}.text"),
                    classification,
                )
            )
        return blocks

    def _tool_call_from_wire(self, value: Any, path: str) -> ToolCall:
        call = expect_object(value, self.name, path)
        if set(call) != {"id", "type", "function"} or call.get("type") != "function":
            raise ProviderAdapterError(self.name, path, "unsupported tool call")
        function = expect_object(call.get("function"), self.name, f"{path}.function")
        if set(function) != {"name", "arguments"}:
            raise ProviderAdapterError(self.name, f"{path}.function", "unknown function field")
        arguments = read_json_text(
            function.get("arguments"), self.name, f"{path}.function.arguments"
        )
        if not isinstance(arguments, dict):
            raise ProviderAdapterError(
                self.name, f"{path}.function.arguments", "expected object JSON"
            )
        return ToolCall(
            expect_string(call.get("id"), self.name, f"{path}.id"),
            expect_string(function.get("name"), self.name, f"{path}.function.name"),
            arguments,
        )

    def _message_to_wire(self, turn: Turn, index: int) -> dict[str, Any]:
        path = f"$.turns[{index}]"
        if turn.role is CanonicalRole.TOOL:
            if len(turn.content) != 1 or not isinstance(turn.content[0], ToolResult):
                raise ProviderAdapterError(
                    self.name, path, "tool turn must contain one tool result"
                )
            result = turn.content[0]
            message: dict[str, Any] = {
                "role": "tool",
                "tool_call_id": result.call_id,
                "content": compact_json(result.result),
            }
            if turn.name:
                message["name"] = turn.name
            return message

        texts = [item for item in turn.content if isinstance(item, TextContent)]
        calls = [item for item in turn.content if isinstance(item, ToolCall)]
        if len(texts) + len(calls) != len(turn.content):
            raise ProviderAdapterError(self.name, path, "unsupported canonical content")
        message = {"role": turn.role.value, "content": None}
        if texts:
            message["content"] = (
                texts[0].text
                if len(texts) == 1
                else [{"type": "text", "text": item.text} for item in texts]
            )
        if calls:
            if turn.role is not CanonicalRole.ASSISTANT:
                raise ProviderAdapterError(self.name, path, "tool calls require assistant role")
            message["tool_calls"] = [
                {
                    "id": call.call_id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": compact_json(call.arguments)},
                }
                for call in calls
            ]
        if turn.name:
            message["name"] = turn.name
        return message

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
        if set(tool) != {"type", "function"}:
            raise ProviderAdapterError(self.name, path, "unknown function tool field")
        function = expect_object(tool.get("function"), self.name, f"{path}.function")
        allowed = {"name", "description", "parameters", "strict"}
        if set(function) - allowed:
            raise ProviderAdapterError(self.name, f"{path}.function", "unknown function field")
        return ToolDefinition(
            name=expect_string(function.get("name"), self.name, f"{path}.function.name"),
            description=expect_string(
                function.get("description", ""), self.name, f"{path}.function.description"
            ),
            input_schema=expect_object(
                function.get("parameters", {"type": "object", "properties": {}}),
                self.name,
                f"{path}.function.parameters",
            ),
            strict=expect_bool(function.get("strict", False), self.name, f"{path}.function.strict"),
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
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": validated_json(tool.input_schema),
                "strict": tool.strict,
            },
        }

    def _tool_choice_from_wire(self, value: Any) -> ToolChoice | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                return ToolChoice(ToolChoiceMode(value))
            except ValueError as exc:
                raise ProviderAdapterError(
                    self.name, "$.tool_choice", "unsupported tool choice"
                ) from exc
        choice = expect_object(value, self.name, "$.tool_choice")
        if set(choice) != {"type", "function"} or choice.get("type") != "function":
            raise ProviderAdapterError(self.name, "$.tool_choice", "unsupported tool choice")
        function = expect_object(choice.get("function"), self.name, "$.tool_choice.function")
        if set(function) != {"name"}:
            raise ProviderAdapterError(self.name, "$.tool_choice.function", "unknown field")
        return ToolChoice(
            ToolChoiceMode.SPECIFIC,
            expect_string(function.get("name"), self.name, "$.tool_choice.function.name"),
        )

    @staticmethod
    def _tool_choice_to_wire(choice: ToolChoice) -> Any:
        if choice.mode is ToolChoiceMode.SPECIFIC:
            return {"type": "function", "function": {"name": choice.name}}
        return choice.mode.value

    def _structured_output_from_wire(self, value: Any) -> StructuredOutput | None:
        if value is None:
            return None
        response_format = expect_object(value, self.name, "$.response_format")
        if (
            set(response_format) != {"type", "json_schema"}
            or response_format.get("type") != "json_schema"
        ):
            raise ProviderAdapterError(
                self.name, "$.response_format", "unsupported response format"
            )
        schema = expect_object(
            response_format.get("json_schema"), self.name, "$.response_format.json_schema"
        )
        if set(schema) != {"name", "strict", "schema"}:
            raise ProviderAdapterError(self.name, "$.response_format.json_schema", "unknown field")
        return StructuredOutput(
            name=expect_string(schema.get("name"), self.name, "$.response_format.json_schema.name"),
            schema=expect_object(
                schema.get("schema"), self.name, "$.response_format.json_schema.schema"
            ),
            strict=expect_bool(
                schema.get("strict"), self.name, "$.response_format.json_schema.strict"
            ),
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
        if "error" in event:
            error = expect_object(event["error"], self.name, "$event.error")
            return (
                ErrorEvent(
                    code=str(error.get("code", "provider_error")),
                    message=str(error.get("message", "provider error")),
                ),
            )
        result: list[CanonicalStreamEvent] = []
        for position, raw_choice in enumerate(
            expect_list(event.get("choices"), self.name, "$event.choices")
        ):
            path = f"$event.choices[{position}]"
            choice = expect_object(raw_choice, self.name, path)
            index = choice.get("index", position)
            if not isinstance(index, int):
                raise ProviderAdapterError(self.name, f"{path}.index", "expected integer")
            delta = expect_object(choice.get("delta", {}), self.name, f"{path}.delta")
            allowed_delta = {"role", "content", "refusal", "function_call", "tool_calls"}
            unknown_delta = set(delta) - allowed_delta
            if unknown_delta:
                field = sorted(unknown_delta)[0]
                raise ProviderAdapterError(
                    self.name, f"{path}.delta.{field}", "unknown stream delta field"
                )
            if "role" in delta:
                role = expect_string(delta["role"], self.name, f"{path}.delta.role")
                if role != "assistant":
                    raise ProviderAdapterError(
                        self.name, f"{path}.delta.role", "unsupported stream role"
                    )
            content = delta.get("content")
            if content is not None:
                delta_path = ("choices", index, "delta", "content")
                fragment = expect_string(content, self.name, f"{path}.delta.content")
                result.append(
                    StructuredDataDelta(path=delta_path, fragment=fragment)
                    if structured_output
                    else TextDelta(path=delta_path, text=fragment)
                )
            refusal = delta.get("refusal")
            if refusal is not None:
                result.append(
                    TextDelta(
                        path=("choices", index, "delta", "refusal"),
                        text=expect_string(refusal, self.name, f"{path}.delta.refusal"),
                    )
                )
            legacy_function = delta.get("function_call")
            if legacy_function is not None:
                function_path = f"{path}.delta.function_call"
                function = expect_object(legacy_function, self.name, function_path)
                if set(function) - {"name", "arguments"}:
                    raise ProviderAdapterError(
                        self.name, function_path, "unknown legacy function_call field"
                    )
                arguments = function.get("arguments")
                if arguments is not None:
                    result.append(
                        ToolArgumentsDelta(
                            call_id=str(function.get("name") or f"choice-{index}-legacy-function"),
                            path=("choices", index, "delta", "function_call", "arguments"),
                            fragment=expect_string(
                                arguments, self.name, f"{function_path}.arguments"
                            ),
                        )
                    )
            for tool_position, raw_tool in enumerate(
                expect_list(delta.get("tool_calls", []), self.name, f"{path}.delta.tool_calls")
            ):
                tool_path = f"{path}.delta.tool_calls[{tool_position}]"
                tool = expect_object(raw_tool, self.name, tool_path)
                if set(tool) - {"index", "id", "type", "function"}:
                    raise ProviderAdapterError(
                        self.name, tool_path, "unknown tool call delta field"
                    )
                function = expect_object(
                    tool.get("function", {}), self.name, f"{tool_path}.function"
                )
                if set(function) - {"name", "arguments"}:
                    raise ProviderAdapterError(
                        self.name, f"{tool_path}.function", "unknown function delta field"
                    )
                fragment = function.get("arguments")
                if fragment is not None:
                    tool_index = tool.get("index", tool_position)
                    call_id = tool.get("id") or f"choice-{index}-tool-{tool_index}"
                    result.append(
                        ToolArgumentsDelta(
                            call_id=str(call_id),
                            path=(
                                "choices",
                                index,
                                "delta",
                                "tool_calls",
                                tool_index,
                                "function",
                                "arguments",
                            ),
                            fragment=expect_string(
                                fragment, self.name, f"{tool_path}.function.arguments"
                            ),
                        )
                    )
            finish_reason = choice.get("finish_reason")
            if finish_reason is not None:
                result.append(FinishEvent(str(finish_reason), path=("choices", index)))
        return tuple(result)


def validate_chat_completion_response(payload: Any) -> None:
    """Fail closed on malformed successful OpenAI-compatible responses."""
    response = expect_object(payload, "openai-chat-response", "$")
    choices = expect_list(response.get("choices"), "openai-chat-response", "$.choices")
    if not choices:
        raise ProviderAdapterError(
            "openai-chat-response", "$.choices", "successful response has no choices"
        )
    for index, raw_choice in enumerate(choices):
        path = f"$.choices[{index}]"
        choice = expect_object(raw_choice, "openai-chat-response", path)
        message = expect_object(choice.get("message"), "openai-chat-response", f"{path}.message")
        if message.get("role") != "assistant":
            raise ProviderAdapterError(
                "openai-chat-response",
                f"{path}.message.role",
                "successful response requires assistant role",
            )
        content = message.get("content")
        if content is not None and not isinstance(content, (str, list)):
            raise ProviderAdapterError(
                "openai-chat-response",
                f"{path}.message.content",
                "content must be text, blocks, or null",
            )
        tool_calls = message.get("tool_calls")
        function_call = message.get("function_call")
        refusal = message.get("refusal")
        if content is None and tool_calls is None and function_call is None and refusal is None:
            raise ProviderAdapterError(
                "openai-chat-response", f"{path}.message", "message has no supported output"
            )
        if refusal is not None and not isinstance(refusal, str):
            raise ProviderAdapterError(
                "openai-chat-response", f"{path}.message.refusal", "refusal must be text"
            )
        if function_call is not None:
            _validate_response_function(function_call, f"{path}.message.function_call")
        if tool_calls is not None:
            for tool_index, raw_tool in enumerate(
                expect_list(tool_calls, "openai-chat-response", f"{path}.message.tool_calls")
            ):
                tool_path = f"{path}.message.tool_calls[{tool_index}]"
                tool = expect_object(raw_tool, "openai-chat-response", tool_path)
                if tool.get("type") != "function" or not isinstance(tool.get("id"), str):
                    raise ProviderAdapterError(
                        "openai-chat-response", tool_path, "invalid function tool call"
                    )
                _validate_response_function(tool.get("function"), f"{tool_path}.function")


def _validate_response_function(value: Any, path: str) -> None:
    function = expect_object(value, "openai-chat-response", path)
    if not isinstance(function.get("name"), str) or not isinstance(function.get("arguments"), str):
        raise ProviderAdapterError(
            "openai-chat-response", path, "function name and arguments must be text"
        )
