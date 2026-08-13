from __future__ import annotations

import copy
import math
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


def validated_json(value: Any, *, path: str = "$") -> Any:
    """Return a detached JSON-compatible value or fail closed."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} must contain finite JSON numbers")
        return value
    if isinstance(value, list):
        return [validated_json(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} must contain only string JSON object keys")
            result[key] = validated_json(item, path=f"{path}.{key}")
        return result
    raise ValueError(f"{path} must be JSON-compatible")


def validated_object_schema(value: Any, *, path: str) -> dict[str, Any]:
    schema = validated_json(value, path=path)
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValueError(f"{path} must be an object schema")
    return schema


class CanonicalRole(StrEnum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class TextClassification(StrEnum):
    USER_TEXT = "user_text"
    INSTRUCTION = "instruction"
    ASSISTANT_TEXT = "assistant_text"
    TOOL_ARGUMENT = "tool_argument"
    TOOL_RESULT = "tool_result"
    STRUCTURED_VALUE = "structured_value"
    PROTOCOL_IDENTIFIER = "protocol_identifier"
    TRUSTED_CONFIG = "trusted_config"


@dataclass(frozen=True, slots=True)
class TextContent:
    text: str
    classification: TextClassification

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise ValueError("text content must be a string")


@dataclass(frozen=True, slots=True)
class StructuredContent:
    value: Any
    classification: TextClassification = TextClassification.STRUCTURED_VALUE

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", validated_json(self.value))


@dataclass(frozen=True, slots=True)
class ToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any]

    def __post_init__(self) -> None:
        if not self.call_id or not self.name:
            raise ValueError("tool calls require an id and name")
        arguments = validated_json(self.arguments, path="$.arguments")
        if not isinstance(arguments, dict):
            raise ValueError("tool call arguments must be a JSON object")
        object.__setattr__(self, "arguments", arguments)


@dataclass(frozen=True, slots=True)
class ToolResult:
    call_id: str
    name: str | None
    result: Any
    is_error: bool = False

    def __post_init__(self) -> None:
        if not self.call_id:
            raise ValueError("tool results require a call id")
        object.__setattr__(self, "result", validated_json(self.result, path="$.result"))


CanonicalContent = TextContent | StructuredContent | ToolCall | ToolResult


@dataclass(frozen=True, slots=True)
class Turn:
    role: CanonicalRole
    content: tuple[CanonicalContent, ...]
    name: str | None = None

    def __post_init__(self) -> None:
        if not self.content:
            raise ValueError("canonical turns cannot be empty")


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    strict: bool = False

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("tool definitions require a name")
        object.__setattr__(
            self,
            "input_schema",
            validated_object_schema(self.input_schema, path="$.input_schema"),
        )


@dataclass(frozen=True, slots=True)
class RemoteToolDefinition:
    provider: str
    kind: str
    configuration: dict[str, Any]
    trusted: bool

    def __post_init__(self) -> None:
        if not self.trusted:
            raise ValueError("remote tools must be explicitly trusted")
        configuration = validated_json(self.configuration, path="$.remote_tool")
        if not isinstance(configuration, dict):
            raise ValueError("remote tool configuration must be a JSON object")
        object.__setattr__(self, "configuration", configuration)


CanonicalTool = ToolDefinition | RemoteToolDefinition


class ToolChoiceMode(StrEnum):
    AUTO = "auto"
    NONE = "none"
    REQUIRED = "required"
    SPECIFIC = "specific"


@dataclass(frozen=True, slots=True)
class ToolChoice:
    mode: ToolChoiceMode
    name: str | None = None

    def __post_init__(self) -> None:
        if self.mode is ToolChoiceMode.SPECIFIC and not self.name:
            raise ValueError("a specific tool choice requires a name")
        if self.mode is not ToolChoiceMode.SPECIFIC and self.name is not None:
            raise ValueError("only a specific tool choice may include a name")


@dataclass(frozen=True, slots=True)
class StructuredOutput:
    name: str
    schema: dict[str, Any]
    strict: bool = True

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("structured output requires a name")
        object.__setattr__(
            self,
            "schema",
            validated_object_schema(self.schema, path="$.structured_output.schema"),
        )


@dataclass(frozen=True, slots=True)
class GenerationSettings:
    max_output_tokens: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    stop_sequences: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.max_output_tokens is not None and self.max_output_tokens < 0:
            raise ValueError("max output tokens cannot be negative")
        for label, value in (("temperature", self.temperature), ("top_p", self.top_p)):
            if value is not None and not math.isfinite(value):
                raise ValueError(f"{label} must be finite")


@dataclass(frozen=True, slots=True)
class OpaqueExtension:
    provider: str
    name: str
    value: Any
    trusted: bool

    def __post_init__(self) -> None:
        if not self.trusted:
            raise ValueError("opaque extensions must be explicitly trusted")
        object.__setattr__(self, "value", validated_json(self.value, path=f"$.{self.name}"))


@dataclass(frozen=True, slots=True)
class CanonicalRequest:
    model: str
    turns: tuple[Turn, ...]
    tools: tuple[CanonicalTool, ...] = ()
    tool_choice: ToolChoice | None = None
    structured_output: StructuredOutput | None = None
    settings: GenerationSettings = field(default_factory=GenerationSettings)
    stream: bool = False
    store: bool = False
    extensions: tuple[OpaqueExtension, ...] = ()
    ir_version: str = "1.0"

    def __post_init__(self) -> None:
        if not self.model:
            raise ValueError("canonical requests require a model")
        if self.ir_version != "1.0":
            raise ValueError("unsupported canonical IR version")
        # Ensure callers cannot mutate nested extension values through retained aliases.
        object.__setattr__(
            self, "extensions", tuple(copy.deepcopy(item) for item in self.extensions)
        )
