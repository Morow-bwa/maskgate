from __future__ import annotations

import re
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

MODEL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class GeminiGenerateContentAdapter:
    name = "gemini-generate-content"
    version = "v1beta-2026-08"

    def __init__(self, policy: AdapterPolicy | None = None) -> None:
        self.policy = policy or AdapterPolicy()

    def from_wire(self, payload: dict[str, Any]) -> CanonicalRequest:
        payload = expect_object(payload, self.name, "$")
        allowed = {
            "model",
            "contents",
            "systemInstruction",
            "tools",
            "toolConfig",
            "generationConfig",
            "stream",
        }
        extensions = extensions_for_unknown_fields(
            payload, allowed, provider=self.name, policy=self.policy
        )
        turns: list[Turn] = []
        if "systemInstruction" in payload:
            turns.append(self._system_from_wire(payload["systemInstruction"]))
        turns.extend(
            self._content_from_wire(item, index)
            for index, item in enumerate(
                expect_list(payload.get("contents"), self.name, "$.contents")
            )
        )
        generation = expect_object(
            payload.get("generationConfig", {}), self.name, "$.generationConfig"
        )
        allowed_generation = {
            "maxOutputTokens",
            "temperature",
            "topP",
            "stopSequences",
            "responseMimeType",
            "responseSchema",
        }
        if set(generation) - allowed_generation:
            field = sorted(set(generation) - allowed_generation)[0]
            raise ProviderAdapterError(
                self.name, f"$.generationConfig.{field}", "unknown generation field"
            )
        return CanonicalRequest(
            model=expect_string(payload.get("model"), self.name, "$.model"),
            turns=tuple(turns),
            tools=self._tools_from_wire(payload.get("tools", [])),
            tool_choice=self._tool_choice_from_wire(payload.get("toolConfig")),
            structured_output=self._structured_output_from_wire(generation),
            settings=generation_settings(
                provider=self.name,
                max_output_tokens=generation.get("maxOutputTokens"),
                temperature=generation.get("temperature"),
                top_p=generation.get("topP"),
                stop=generation.get("stopSequences"),
            ),
            stream=expect_bool(payload.get("stream", False), self.name, "$.stream"),
            store=False,
            extensions=extensions,
        )

    def to_wire(self, request: CanonicalRequest) -> dict[str, Any]:
        if request.store and not self.policy.allow_provider_storage:
            raise ProviderAdapterError(self.name, "$.store", "provider storage is disabled")
        system: list[dict[str, str]] = []
        contents: list[dict[str, Any]] = []
        for index, turn in enumerate(request.turns):
            if turn.role in {CanonicalRole.SYSTEM, CanonicalRole.DEVELOPER}:
                if contents or any(not isinstance(item, TextContent) for item in turn.content):
                    raise ProviderAdapterError(
                        self.name, f"$.turns[{index}]", "system instructions must precede contents"
                    )
                system.extend(
                    {"text": item.text} for item in turn.content if isinstance(item, TextContent)
                )
            else:
                contents.append(self._content_to_wire(turn, index))
        payload: dict[str, Any] = {
            "contents": contents,
        }
        if system:
            payload["systemInstruction"] = {"parts": system}
        if request.tools:
            function_declarations: list[dict[str, Any]] = []
            remote_tools: list[dict[str, Any]] = []
            for index, tool in enumerate(request.tools):
                if isinstance(tool, RemoteToolDefinition):
                    remote_tools.append(
                        emit_remote_tool(
                            tool, provider=self.name, policy=self.policy, path=f"$.tools[{index}]"
                        )
                    )
                else:
                    if tool.strict:
                        raise ProviderAdapterError(
                            self.name, f"$.tools[{index}].strict", "strict flag is not represented"
                        )
                    function_declarations.append(
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": validated_json(tool.input_schema),
                        }
                    )
            payload["tools"] = (
                [{"functionDeclarations": function_declarations}] if function_declarations else []
            ) + remote_tools
        if request.tool_choice is not None:
            payload["toolConfig"] = self._tool_choice_to_wire(request.tool_choice)
        generation: dict[str, Any] = {}
        settings = request.settings
        if settings.max_output_tokens is not None:
            generation["maxOutputTokens"] = settings.max_output_tokens
        if settings.temperature is not None:
            generation["temperature"] = settings.temperature
        if settings.top_p is not None:
            generation["topP"] = settings.top_p
        if settings.stop_sequences:
            generation["stopSequences"] = list(settings.stop_sequences)
        if request.structured_output is not None:
            if request.structured_output.name != "response":
                raise ProviderAdapterError(
                    self.name,
                    "$.structured_output.name",
                    "Gemini legacy does not carry schema names",
                )
            generation["responseMimeType"] = "application/json"
            generation["responseSchema"] = validated_json(request.structured_output.schema)
        if generation:
            payload["generationConfig"] = generation
        emit_extensions(payload, request, provider=self.name, policy=self.policy)
        return payload

    def target_for(self, request: CanonicalRequest) -> str:
        """Return the provider target; model and stream are not JSON body fields."""
        model = request.model.removeprefix("models/")
        if not MODEL_NAME_PATTERN.fullmatch(model):
            raise ProviderAdapterError(self.name, "$.model", "unsupported model name")
        operation = "streamGenerateContent?alt=sse" if request.stream else "generateContent"
        return f"/v1beta/models/{model}:{operation}"

    def _system_from_wire(self, value: Any) -> Turn:
        system = expect_object(value, self.name, "$.systemInstruction")
        if set(system) != {"parts"}:
            raise ProviderAdapterError(self.name, "$.systemInstruction", "unknown system field")
        texts: list[TextContent] = []
        for index, raw_part in enumerate(
            expect_list(system.get("parts"), self.name, "$.systemInstruction.parts")
        ):
            path = f"$.systemInstruction.parts[{index}]"
            part = expect_object(raw_part, self.name, path)
            if set(part) != {"text"}:
                raise ProviderAdapterError(self.name, path, "unsupported system part")
            texts.append(
                TextContent(
                    expect_string(part.get("text"), self.name, f"{path}.text"),
                    classification_for_role(CanonicalRole.SYSTEM),
                )
            )
        return Turn(CanonicalRole.SYSTEM, tuple(texts))

    def _content_from_wire(self, value: Any, index: int) -> Turn:
        path = f"$.contents[{index}]"
        content = expect_object(value, self.name, path)
        if set(content) != {"role", "parts"}:
            raise ProviderAdapterError(self.name, path, "unknown content field")
        role_value = expect_string(content.get("role"), self.name, f"{path}.role")
        if role_value not in {"user", "model"}:
            raise ProviderAdapterError(self.name, f"{path}.role", "unsupported role")
        role = CanonicalRole.ASSISTANT if role_value == "model" else CanonicalRole.USER
        blocks: list[TextContent | ToolCall | ToolResult] = []
        for part_index, raw_part in enumerate(
            expect_list(content.get("parts"), self.name, f"{path}.parts")
        ):
            part_path = f"{path}.parts[{part_index}]"
            part = expect_object(raw_part, self.name, part_path)
            if set(part) == {"text"}:
                blocks.append(
                    TextContent(
                        expect_string(part.get("text"), self.name, f"{part_path}.text"),
                        classification_for_role(role),
                    )
                )
            elif set(part) == {"functionCall"}:
                if role is not CanonicalRole.ASSISTANT:
                    raise ProviderAdapterError(
                        self.name, part_path, "functionCall requires model role"
                    )
                call = expect_object(
                    part.get("functionCall"), self.name, f"{part_path}.functionCall"
                )
                if set(call) != {"id", "name", "args"}:
                    raise ProviderAdapterError(
                        self.name, f"{part_path}.functionCall", "unknown field"
                    )
                blocks.append(
                    ToolCall(
                        expect_string(call.get("id"), self.name, f"{part_path}.functionCall.id"),
                        expect_string(
                            call.get("name"), self.name, f"{part_path}.functionCall.name"
                        ),
                        expect_object(
                            call.get("args"), self.name, f"{part_path}.functionCall.args"
                        ),
                    )
                )
            elif set(part) == {"functionResponse"}:
                if role is not CanonicalRole.USER:
                    raise ProviderAdapterError(
                        self.name, part_path, "functionResponse requires user role"
                    )
                response = expect_object(
                    part.get("functionResponse"), self.name, f"{part_path}.functionResponse"
                )
                if set(response) != {"id", "name", "response"}:
                    raise ProviderAdapterError(
                        self.name, f"{part_path}.functionResponse", "unknown field"
                    )
                blocks.append(
                    ToolResult(
                        expect_string(
                            response.get("id"), self.name, f"{part_path}.functionResponse.id"
                        ),
                        expect_string(
                            response.get("name"), self.name, f"{part_path}.functionResponse.name"
                        ),
                        validated_json(
                            response.get("response"), path=f"{part_path}.functionResponse.response"
                        ),
                    )
                )
            else:
                raise ProviderAdapterError(self.name, part_path, "unsupported content part")
        if len(blocks) == 1 and isinstance(blocks[0], ToolResult):
            return Turn(CanonicalRole.TOOL, tuple(blocks))
        if any(isinstance(item, ToolResult) for item in blocks):
            raise ProviderAdapterError(self.name, path, "tool result cannot share a canonical turn")
        return Turn(role, tuple(blocks))

    def _content_to_wire(self, turn: Turn, index: int) -> dict[str, Any]:
        path = f"$.turns[{index}]"
        role = "model" if turn.role is CanonicalRole.ASSISTANT else "user"
        if turn.role not in {CanonicalRole.USER, CanonicalRole.ASSISTANT, CanonicalRole.TOOL}:
            raise ProviderAdapterError(self.name, path, "unsupported role")
        parts: list[dict[str, Any]] = []
        for item in turn.content:
            if isinstance(item, TextContent):
                parts.append({"text": item.text})
            elif isinstance(item, ToolCall) and turn.role is CanonicalRole.ASSISTANT:
                parts.append(
                    {
                        "functionCall": {
                            "id": item.call_id,
                            "name": item.name,
                            "args": validated_json(item.arguments),
                        }
                    }
                )
            elif isinstance(item, ToolResult) and turn.role is CanonicalRole.TOOL:
                if not item.name:
                    raise ProviderAdapterError(
                        self.name, path, "Gemini tool results require a name"
                    )
                parts.append(
                    {
                        "functionResponse": {
                            "id": item.call_id,
                            "name": item.name,
                            "response": validated_json(item.result),
                        }
                    }
                )
            else:
                raise ProviderAdapterError(self.name, path, "unsupported canonical content")
        return {"role": role, "parts": parts}

    def _tools_from_wire(self, value: Any) -> tuple[ToolDefinition | RemoteToolDefinition, ...]:
        result: list[ToolDefinition | RemoteToolDefinition] = []
        for index, raw_tool in enumerate(expect_list(value, self.name, "$.tools")):
            path = f"$.tools[{index}]"
            tool = expect_object(raw_tool, self.name, path)
            if set(tool) == {"functionDeclarations"}:
                for declaration_index, raw_declaration in enumerate(
                    expect_list(
                        tool["functionDeclarations"], self.name, f"{path}.functionDeclarations"
                    )
                ):
                    declaration_path = f"{path}.functionDeclarations[{declaration_index}]"
                    declaration = expect_object(raw_declaration, self.name, declaration_path)
                    if set(declaration) != {"name", "description", "parameters"}:
                        raise ProviderAdapterError(
                            self.name, declaration_path, "unknown function field"
                        )
                    result.append(
                        ToolDefinition(
                            expect_string(
                                declaration.get("name"), self.name, f"{declaration_path}.name"
                            ),
                            expect_string(
                                declaration.get("description", ""),
                                self.name,
                                f"{declaration_path}.description",
                            ),
                            expect_object(
                                declaration.get("parameters"),
                                self.name,
                                f"{declaration_path}.parameters",
                            ),
                            False,
                        )
                    )
            else:
                kind = next(iter(tool), "unknown")
                result.append(
                    remote_tool(
                        provider=self.name,
                        kind=kind,
                        configuration=tool,
                        policy=self.policy,
                        path=path,
                    )
                )
        return tuple(result)

    def _tool_choice_from_wire(self, value: Any) -> ToolChoice | None:
        if value is None:
            return None
        config = expect_object(value, self.name, "$.toolConfig")
        if set(config) != {"functionCallingConfig"}:
            raise ProviderAdapterError(self.name, "$.toolConfig", "unknown tool config")
        function = expect_object(
            config.get("functionCallingConfig"), self.name, "$.toolConfig.functionCallingConfig"
        )
        allowed = {"mode", "allowedFunctionNames"}
        if set(function) - allowed:
            raise ProviderAdapterError(
                self.name, "$.toolConfig.functionCallingConfig", "unknown field"
            )
        mode = expect_string(
            function.get("mode"), self.name, "$.toolConfig.functionCallingConfig.mode"
        ).upper()
        if mode == "ANY" and "allowedFunctionNames" in function:
            names = expect_list(
                function["allowedFunctionNames"],
                self.name,
                "$.toolConfig.functionCallingConfig.allowedFunctionNames",
            )
            if len(names) != 1:
                raise ProviderAdapterError(
                    self.name, "$.toolConfig", "specific choice needs one function"
                )
            return ToolChoice(
                ToolChoiceMode.SPECIFIC,
                expect_string(
                    names[0],
                    self.name,
                    "$.toolConfig.functionCallingConfig.allowedFunctionNames[0]",
                ),
            )
        mapping = {
            "AUTO": ToolChoiceMode.AUTO,
            "NONE": ToolChoiceMode.NONE,
            "ANY": ToolChoiceMode.REQUIRED,
        }
        if mode not in mapping or "allowedFunctionNames" in function:
            raise ProviderAdapterError(self.name, "$.toolConfig", "unsupported tool choice")
        return ToolChoice(mapping[mode])

    @staticmethod
    def _tool_choice_to_wire(choice: ToolChoice) -> dict[str, Any]:
        if choice.mode is ToolChoiceMode.SPECIFIC:
            return {"functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": [choice.name]}}
        mapping = {
            ToolChoiceMode.AUTO: "AUTO",
            ToolChoiceMode.NONE: "NONE",
            ToolChoiceMode.REQUIRED: "ANY",
        }
        return {"functionCallingConfig": {"mode": mapping[choice.mode]}}

    def _structured_output_from_wire(self, generation: dict[str, Any]) -> StructuredOutput | None:
        mime = generation.get("responseMimeType")
        schema = generation.get("responseSchema")
        if mime is None and schema is None:
            return None
        if mime != "application/json" or schema is None:
            raise ProviderAdapterError(
                self.name, "$.generationConfig", "incomplete structured output"
            )
        return StructuredOutput(
            "response",
            expect_object(schema, self.name, "$.generationConfig.responseSchema"),
            True,
        )

    def parse_stream_event(
        self, event: dict[str, Any], *, structured_output: bool = False
    ) -> tuple[CanonicalStreamEvent, ...]:
        event = expect_object(event, self.name, "$event")
        if "error" in event:
            error = expect_object(event["error"], self.name, "$event.error")
            return (
                ErrorEvent(
                    str(error.get("code", "provider_error")),
                    str(error.get("message", "provider error")),
                ),
            )
        result: list[CanonicalStreamEvent] = []
        for candidate_index, raw_candidate in enumerate(
            expect_list(event.get("candidates", []), self.name, "$event.candidates")
        ):
            path = f"$event.candidates[{candidate_index}]"
            candidate = expect_object(raw_candidate, self.name, path)
            content = expect_object(candidate.get("content", {}), self.name, f"{path}.content")
            for part_index, raw_part in enumerate(
                expect_list(content.get("parts", []), self.name, f"{path}.content.parts")
            ):
                part = expect_object(raw_part, self.name, f"{path}.content.parts[{part_index}]")
                if set(part) == {"text"}:
                    delta_path = (
                        "candidates",
                        candidate_index,
                        "content",
                        "parts",
                        part_index,
                        "text",
                    )
                    fragment = expect_string(
                        part.get("text"),
                        self.name,
                        f"{path}.content.parts[{part_index}].text",
                    )
                    result.append(
                        StructuredDataDelta(path=delta_path, fragment=fragment)
                        if structured_output
                        else TextDelta(path=delta_path, text=fragment)
                    )
                elif set(part) == {"functionCall"}:
                    call = expect_object(
                        part["functionCall"],
                        self.name,
                        f"{path}.content.parts[{part_index}].functionCall",
                    )
                    result.append(
                        ToolArgumentsDelta(
                            call_id=expect_string(
                                call.get("id"), self.name, f"{path}.functionCall.id"
                            ),
                            path=(
                                "candidates",
                                candidate_index,
                                "content",
                                "parts",
                                part_index,
                                "functionCall",
                                "args",
                            ),
                            fragment=compact_json(
                                expect_object(
                                    call.get("args"), self.name, f"{path}.functionCall.args"
                                )
                            ),
                        )
                    )
                else:
                    raise ProviderAdapterError(
                        self.name, f"{path}.content.parts[{part_index}]", "unknown stream part"
                    )
            if candidate.get("finishReason") is not None:
                result.append(
                    FinishEvent(
                        str(candidate["finishReason"]), path=("candidates", candidate_index)
                    )
                )
        return tuple(result)
