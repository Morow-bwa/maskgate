from __future__ import annotations

import pytest

from app.privacy.ir import (
    CanonicalRequest,
    CanonicalRole,
    ErrorEvent,
    FinishEvent,
    GenerationSettings,
    OpaqueExtension,
    StreamEventKind,
    StructuredContent,
    StructuredDataDelta,
    StructuredOutput,
    TextClassification,
    TextContent,
    TextDelta,
    ToolArgumentsDelta,
    ToolCall,
    ToolDefinition,
    ToolResult,
    Turn,
)


def test_canonical_ir_preserves_typed_content_and_tool_structures() -> None:
    request = CanonicalRequest(
        model="model-test",
        turns=(
            Turn(
                role=CanonicalRole.SYSTEM,
                content=(TextContent("Keep answers short", TextClassification.INSTRUCTION),),
            ),
            Turn(
                role=CanonicalRole.USER,
                content=(
                    TextContent("Weather in Paris", TextClassification.USER_TEXT),
                    StructuredContent({"units": "celsius"}),
                ),
            ),
            Turn(
                role=CanonicalRole.ASSISTANT,
                content=(ToolCall("call-1", "weather", {"city": "Paris"}),),
            ),
            Turn(
                role=CanonicalRole.TOOL,
                content=(ToolResult("call-1", "weather", {"temperature": 21}),),
            ),
        ),
        tools=(
            ToolDefinition(
                name="weather",
                description="Read weather",
                input_schema={
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"],
                    "additionalProperties": False,
                },
                strict=True,
            ),
        ),
        structured_output=StructuredOutput(
            name="forecast",
            schema={
                "type": "object",
                "properties": {"temperature": {"type": "number"}},
                "required": ["temperature"],
                "additionalProperties": False,
            },
            strict=True,
        ),
        settings=GenerationSettings(max_output_tokens=256, temperature=0.2),
    )

    assert request.turns[0].content[0].classification is TextClassification.INSTRUCTION
    assert request.turns[2].content[0].arguments == {"city": "Paris"}
    assert request.turns[3].content[0].result == {"temperature": 21}
    assert request.tools[0].input_schema["additionalProperties"] is False
    assert request.structured_output.schema["required"] == ["temperature"]


def test_ir_copies_json_values_and_rejects_non_json_or_invalid_schemas() -> None:
    source = {"nested": ["before"]}
    content = StructuredContent(source)
    source["nested"].append("after")
    assert content.value == {"nested": ["before"]}

    with pytest.raises(ValueError, match="JSON-compatible"):
        StructuredContent({"bad": object()})
    with pytest.raises(ValueError, match="object schema"):
        ToolDefinition("tool", "desc", {"type": "array"})
    with pytest.raises(ValueError, match="object schema"):
        StructuredOutput("result", {"type": "string"})


def test_opaque_extensions_require_an_explicit_trust_marker() -> None:
    with pytest.raises(ValueError, match="explicitly trusted"):
        OpaqueExtension(provider="openai-responses", name="metadata", value={}, trusted=False)

    extension = OpaqueExtension(
        provider="openai-responses",
        name="metadata",
        value={"trace": "synthetic"},
        trusted=True,
    )
    assert extension.trusted is True


def test_stream_event_types_are_explicit_and_path_aware() -> None:
    events = (
        TextDelta(path=("choices", 1, "delta", "content"), text="hello"),
        ToolArgumentsDelta(call_id="call-1", path=("tools", 0), fragment='{"x":'),
        StructuredDataDelta(path=("output", 0), fragment='{"answer":'),
        FinishEvent(reason="stop"),
        ErrorEvent(code="invalid_stream", message="bad event"),
    )

    assert [event.kind for event in events] == [
        StreamEventKind.TEXT_DELTA,
        StreamEventKind.TOOL_ARGUMENTS_DELTA,
        StreamEventKind.STRUCTURED_DATA_DELTA,
        StreamEventKind.FINISH,
        StreamEventKind.ERROR,
    ]
