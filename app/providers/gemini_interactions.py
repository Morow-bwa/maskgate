from __future__ import annotations

import json
from typing import Any

from app.privacy.ir import (
    CanonicalRequest,
    CanonicalRole,
    CanonicalStreamEvent,
    ErrorEvent,
    FinishEvent,
    OpaqueExtension,
    RemoteToolDefinition,
    StructuredDataDelta,
    StructuredOutput,
    TextContent,
    TextDelta,
    ToolArgumentsDelta,
    ToolCall,
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
    remote_tool,
)
from .common import classification_for_role, generation_settings, parse_simple_tool_choice


class GeminiInteractionsAdapter:
    """Experimental pure Adapter for the current Gemini Interactions Wire format."""

    name = "gemini-interactions"
    version = "v1-2026-08"
    experimental = True

    def __init__(self, policy: AdapterPolicy | None = None) -> None:
        self.policy = policy or AdapterPolicy()

    def from_wire(self, payload: dict[str, Any]) -> CanonicalRequest:
        payload = expect_object(payload, self.name, "$")
        allowed = {
            "model",
            "input",
            "system_instruction",
            "tools",
            "tool_choice",
            "response_format",
            "generation_config",
            "stream",
            "store",
            "previous_interaction_id",
        }
        extensions = list(
            extensions_for_unknown_fields(payload, allowed, provider=self.name, policy=self.policy)
        )
        store = enforce_storage(payload.get("store"), self.name, self.policy, "$.store")
        previous_id = payload.get("previous_interaction_id")
        if previous_id is not None:
            if (
                not self.policy.allow_provider_storage
                or "previous_interaction_id" not in self.policy.safe_extension_fields
            ):
                raise ProviderAdapterError(
                    self.name,
                    "$.previous_interaction_id",
                    "server-side state requires an explicit reviewed storage policy",
                )
            if not store:
                raise ProviderAdapterError(
                    self.name,
                    "$.previous_interaction_id",
                    "server-side state requires storage to be enabled",
                )
            extensions.append(
                OpaqueExtension(
                    provider=self.name,
                    name="previous_interaction_id",
                    value=expect_string(previous_id, self.name, "$.previous_interaction_id"),
                    trusted=True,
                )
            )

        turns: list[Turn] = []
        if "system_instruction" in payload:
            turns.append(
                Turn(
                    CanonicalRole.SYSTEM,
                    (
                        TextContent(
                            expect_string(
                                payload["system_instruction"], self.name, "$.system_instruction"
                            ),
                            classification_for_role(CanonicalRole.SYSTEM),
                        ),
                    ),
                )
            )
        turns.extend(self._input_from_wire(payload.get("input")))
        generation = expect_object(
            payload.get("generation_config", {}), self.name, "$.generation_config"
        )
        allowed_generation = {"max_output_tokens", "temperature", "top_p", "stop_sequences"}
        if set(generation) - allowed_generation:
            field = sorted(set(generation) - allowed_generation)[0]
            raise ProviderAdapterError(
                self.name, f"$.generation_config.{field}", "unknown generation field"
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
            tool_choice=parse_simple_tool_choice(
                payload.get("tool_choice"), self.name, "$.tool_choice"
            ),
            structured_output=self._structured_output_from_wire(payload.get("response_format")),
            settings=generation_settings(
                provider=self.name,
                max_output_tokens=generation.get("max_output_tokens"),
                temperature=generation.get("temperature"),
                top_p=generation.get("top_p"),
                stop=generation.get("stop_sequences"),
            ),
            stream=expect_bool(payload.get("stream", False), self.name, "$.stream"),
            store=store,
            extensions=tuple(extensions),
        )

    def to_wire(self, request: CanonicalRequest) -> dict[str, Any]:
        if request.store and not self.policy.allow_provider_storage:
            raise ProviderAdapterError(self.name, "$.store", "provider storage is disabled")
        instructions: list[str] = []
        inputs: list[dict[str, Any]] = []
        for index, turn in enumerate(request.turns):
            if turn.role in {CanonicalRole.SYSTEM, CanonicalRole.DEVELOPER}:
                if (
                    instructions
                    or inputs
                    or any(not isinstance(item, TextContent) for item in turn.content)
                ):
                    raise ProviderAdapterError(
                        self.name, f"$.turns[{index}]", "one leading text instruction is supported"
                    )
                instructions.append(
                    "\n".join(item.text for item in turn.content if isinstance(item, TextContent))
                )
            else:
                inputs.extend(self._turn_to_inputs(turn, index))
        payload: dict[str, Any] = {
            "model": request.model,
            "input": inputs,
            "stream": request.stream,
            "store": request.store,
        }
        if instructions:
            payload["system_instruction"] = instructions[0]
        if request.tools:
            payload["tools"] = [
                self._tool_to_wire(tool, index) for index, tool in enumerate(request.tools)
            ]
        if request.tool_choice is not None:
            if request.tool_choice.name is not None:
                raise ProviderAdapterError(
                    self.name, "$.tool_choice", "specific tool choice is not implemented"
                )
            payload["tool_choice"] = request.tool_choice.mode.value
        if request.structured_output is not None:
            if request.structured_output.name != "response":
                raise ProviderAdapterError(
                    self.name, "$.structured_output.name", "Gemini does not carry schema names"
                )
            payload["response_format"] = {
                "type": "text",
                "mime_type": "application/json",
                "schema": validated_json(request.structured_output.schema),
            }
        generation: dict[str, Any] = {}
        settings = request.settings
        if settings.max_output_tokens is not None:
            generation["max_output_tokens"] = settings.max_output_tokens
        if settings.temperature is not None:
            generation["temperature"] = settings.temperature
        if settings.top_p is not None:
            generation["top_p"] = settings.top_p
        if settings.stop_sequences:
            generation["stop_sequences"] = list(settings.stop_sequences)
        if generation:
            payload["generation_config"] = generation
        emit_extensions(payload, request, provider=self.name, policy=self.policy)
        if "previous_interaction_id" in payload and not request.store:
            raise ProviderAdapterError(
                self.name,
                "$.previous_interaction_id",
                "server-side state requires storage to be enabled",
            )
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
        for index, raw_step in enumerate(expect_list(value, self.name, "$.input")):
            path = f"$.input[{index}]"
            step = expect_object(raw_step, self.name, path)
            step_type = expect_string(step.get("type"), self.name, f"{path}.type")
            if step_type in {"user_input", "model_output"}:
                if set(step) != {"type", "content"}:
                    raise ProviderAdapterError(self.name, path, "unknown text step field")
                role = CanonicalRole.USER if step_type == "user_input" else CanonicalRole.ASSISTANT
                blocks: list[TextContent] = []
                for block_index, raw_block in enumerate(
                    expect_list(step.get("content"), self.name, f"{path}.content")
                ):
                    block_path = f"{path}.content[{block_index}]"
                    block = expect_object(raw_block, self.name, block_path)
                    if set(block) != {"type", "text"} or block.get("type") != "text":
                        raise ProviderAdapterError(
                            self.name,
                            block_path,
                            "unsupported media or opaque input block",
                        )
                    blocks.append(
                        TextContent(
                            expect_string(block.get("text"), self.name, f"{block_path}.text"),
                            classification_for_role(role),
                        )
                    )
                turns.append(Turn(role, tuple(blocks)))
            elif step_type == "function_call":
                if set(step) != {"type", "id", "name", "arguments"}:
                    raise ProviderAdapterError(self.name, path, "unknown function call field")
                turns.append(
                    Turn(
                        CanonicalRole.ASSISTANT,
                        (
                            ToolCall(
                                expect_string(step.get("id"), self.name, f"{path}.id"),
                                expect_string(step.get("name"), self.name, f"{path}.name"),
                                expect_object(
                                    step.get("arguments"), self.name, f"{path}.arguments"
                                ),
                            ),
                        ),
                    )
                )
            elif step_type == "function_result":
                if set(step) != {"type", "call_id", "name", "result"}:
                    raise ProviderAdapterError(self.name, path, "unknown function result field")
                turns.append(
                    Turn(
                        CanonicalRole.TOOL,
                        (
                            ToolResult(
                                expect_string(step.get("call_id"), self.name, f"{path}.call_id"),
                                expect_string(step.get("name"), self.name, f"{path}.name"),
                                self._result_from_wire(step.get("result"), f"{path}.result"),
                            ),
                        ),
                    )
                )
            else:
                raise ProviderAdapterError(self.name, path, "unsupported input step")
        return turns

    def _turn_to_inputs(self, turn: Turn, index: int) -> list[dict[str, Any]]:
        path = f"$.turns[{index}]"
        if turn.role is CanonicalRole.TOOL:
            if len(turn.content) != 1 or not isinstance(turn.content[0], ToolResult):
                raise ProviderAdapterError(self.name, path, "tool turn must contain one result")
            result = turn.content[0]
            if not result.name:
                raise ProviderAdapterError(self.name, path, "Gemini tool results require a name")
            return [
                {
                    "type": "function_result",
                    "name": result.name,
                    "call_id": result.call_id,
                    "result": [{"type": "text", "text": compact_json(result.result)}],
                }
            ]
        result: list[dict[str, Any]] = []
        texts = [item for item in turn.content if isinstance(item, TextContent)]
        calls = [item for item in turn.content if isinstance(item, ToolCall)]
        if len(texts) + len(calls) != len(turn.content):
            raise ProviderAdapterError(self.name, path, "unsupported canonical content")
        if texts:
            if turn.role not in {CanonicalRole.USER, CanonicalRole.ASSISTANT}:
                raise ProviderAdapterError(self.name, path, "unsupported text role")
            result.append(
                {
                    "type": "user_input" if turn.role is CanonicalRole.USER else "model_output",
                    "content": [{"type": "text", "text": item.text} for item in texts],
                }
            )
        for call in calls:
            if turn.role is not CanonicalRole.ASSISTANT:
                raise ProviderAdapterError(self.name, path, "tool calls require assistant role")
            result.append(
                {
                    "type": "function_call",
                    "id": call.call_id,
                    "name": call.name,
                    "arguments": validated_json(call.arguments),
                }
            )
        return result

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
        allowed = {"type", "name", "description", "parameters"}
        if set(tool) - allowed:
            raise ProviderAdapterError(self.name, path, "unknown function tool field")
        return ToolDefinition(
            expect_string(tool.get("name"), self.name, f"{path}.name"),
            expect_string(tool.get("description", ""), self.name, f"{path}.description"),
            expect_object(tool.get("parameters"), self.name, f"{path}.parameters"),
            False,
        )

    def _tool_to_wire(
        self, tool: ToolDefinition | RemoteToolDefinition, index: int
    ) -> dict[str, Any]:
        if isinstance(tool, RemoteToolDefinition):
            return emit_remote_tool(
                tool, provider=self.name, policy=self.policy, path=f"$.tools[{index}]"
            )
        if tool.strict:
            raise ProviderAdapterError(
                self.name, f"$.tools[{index}].strict", "strict flag is not represented"
            )
        return {
            "type": "function",
            "name": tool.name,
            "description": tool.description,
            "parameters": validated_json(tool.input_schema),
        }

    def _structured_output_from_wire(self, value: Any) -> StructuredOutput | None:
        if value is None:
            return None
        output = expect_object(value, self.name, "$.response_format")
        if set(output) != {"type", "mime_type", "schema"}:
            raise ProviderAdapterError(
                self.name, "$.response_format", "unknown response format field"
            )
        if output.get("type") != "text" or output.get("mime_type") != "application/json":
            raise ProviderAdapterError(
                self.name, "$.response_format", "unsupported response format"
            )
        return StructuredOutput(
            "response",
            expect_object(output.get("schema"), self.name, "$.response_format.schema"),
            True,
        )

    def _result_from_wire(self, value: Any, path: str) -> Any:
        texts: list[str] = []
        for index, raw_block in enumerate(expect_list(value, self.name, path)):
            block_path = f"{path}[{index}]"
            block = expect_object(raw_block, self.name, block_path)
            if set(block) != {"type", "text"} or block.get("type") != "text":
                raise ProviderAdapterError(self.name, block_path, "unsupported tool result block")
            texts.append(expect_string(block.get("text"), self.name, f"{block_path}.text"))
        combined = "".join(texts)
        try:
            return validated_json(json.loads(combined), path=path)
        except (json.JSONDecodeError, ValueError):
            return combined

    def parse_stream_event(
        self, event: dict[str, Any], *, structured_output: bool = False
    ) -> tuple[CanonicalStreamEvent, ...]:
        event = expect_object(event, self.name, "$event")
        event_type = expect_string(event.get("event_type"), self.name, "$event.event_type")
        if event_type == "step.delta":
            index = event.get("index", 0)
            delta = expect_object(event.get("delta"), self.name, "$event.delta")
            delta_type = expect_string(delta.get("type"), self.name, "$event.delta.type")
            if delta_type == "text":
                path = ("steps", index, "text")
                fragment = expect_string(delta.get("text"), self.name, "$event.delta.text")
                return (
                    StructuredDataDelta(path=path, fragment=fragment)
                    if structured_output
                    else TextDelta(path=path, text=fragment),
                )
            if delta_type == "arguments_delta":
                return (
                    ToolArgumentsDelta(
                        call_id=f"step-{index}",
                        path=("steps", index, "arguments"),
                        fragment=expect_string(
                            delta.get("arguments"), self.name, "$event.delta.arguments"
                        ),
                    ),
                )
            raise ProviderAdapterError(
                self.name, "$event.delta.type", "unsupported media or opaque stream delta"
            )
        if event_type == "interaction.completed":
            interaction = expect_object(
                event.get("interaction", {}), self.name, "$event.interaction"
            )
            return (FinishEvent(str(interaction.get("status", "completed"))),)
        if event_type == "error":
            error = expect_object(event.get("error", {}), self.name, "$event.error")
            return (
                ErrorEvent(
                    str(error.get("code", "provider_error")),
                    str(error.get("message", "provider error")),
                ),
            )
        if event_type in {
            "interaction.created",
            "interaction.status_update",
            "step.start",
            "step.stop",
            "done",
        }:
            return ()
        raise ProviderAdapterError(self.name, "$event.event_type", "unknown stream event")
