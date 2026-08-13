from __future__ import annotations

import pytest

from app.privacy.ir import (
    CanonicalRole,
    ErrorEvent,
    FinishEvent,
    StructuredDataDelta,
    TextDelta,
    ToolArgumentsDelta,
    ToolCall,
    ToolResult,
)
from app.providers import (
    AdapterPolicy,
    AnthropicMessagesAdapter,
    GeminiGenerateContentAdapter,
    GeminiInteractionsAdapter,
    OpenAIChatCompletionsAdapter,
    OpenAIResponsesAdapter,
    ProviderAdapterError,
)

SCHEMA = {
    "type": "object",
    "properties": {"city": {"type": "string"}},
    "required": ["city"],
    "additionalProperties": False,
}


@pytest.mark.parametrize(
    ("adapter", "payload"),
    [
        (
            OpenAIChatCompletionsAdapter(),
            {
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "hello"}],
                "unknown_payload": "must-not-disappear",
            },
        ),
        (
            OpenAIResponsesAdapter(),
            {"model": "gpt-test", "input": "hello", "unknown_payload": "must-not-disappear"},
        ),
        (
            AnthropicMessagesAdapter(),
            {
                "model": "claude-test",
                "max_tokens": 128,
                "messages": [{"role": "user", "content": "hello"}],
                "unknown_payload": "must-not-disappear",
            },
        ),
        (
            GeminiGenerateContentAdapter(),
            {
                "model": "gemini-test",
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
                "unknownPayload": "must-not-disappear",
            },
        ),
        (
            GeminiInteractionsAdapter(),
            {"model": "gemini-test", "input": "hello", "unknown_payload": "must-not-disappear"},
        ),
    ],
)
def test_unknown_wire_fields_fail_closed(adapter: object, payload: dict[str, object]) -> None:
    with pytest.raises(ProviderAdapterError, match="unknown"):
        adapter.from_wire(payload)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("adapter", "payload"),
    [
        (
            OpenAIChatCompletionsAdapter(),
            {"model": "gpt-test", "messages": [], "store": True},
        ),
        (
            OpenAIResponsesAdapter(),
            {"model": "gpt-test", "input": "hello", "store": True},
        ),
        (
            GeminiInteractionsAdapter(),
            {"model": "gemini-test", "input": "hello", "store": True},
        ),
    ],
)
def test_provider_storage_is_disabled_by_default(
    adapter: object, payload: dict[str, object]
) -> None:
    with pytest.raises(ProviderAdapterError, match="storage"):
        adapter.from_wire(payload)  # type: ignore[attr-defined]


def test_gemini_interactions_server_state_requires_two_explicit_policy_controls() -> None:
    payload = {
        "model": "gemini-test",
        "input": "hello",
        "store": True,
        "previous_interaction_id": "interaction-1",
    }
    with pytest.raises(ProviderAdapterError, match="storage"):
        GeminiInteractionsAdapter().from_wire(payload)

    storage_only = GeminiInteractionsAdapter(AdapterPolicy(allow_provider_storage=True))
    with pytest.raises(ProviderAdapterError, match="reviewed storage policy"):
        storage_only.from_wire(payload)

    reviewed = GeminiInteractionsAdapter(
        AdapterPolicy(
            allow_provider_storage=True,
            safe_extension_fields=frozenset({"previous_interaction_id"}),
        )
    )
    request = reviewed.from_wire(payload)
    assert reviewed.to_wire(request)["previous_interaction_id"] == "interaction-1"


def test_gemini_interactions_labels_and_media_fail_closed_by_default() -> None:
    adapter = GeminiInteractionsAdapter()
    with pytest.raises(ProviderAdapterError, match="unknown unsafe field"):
        adapter.from_wire({"model": "gemini-test", "input": "hello", "labels": {"team": "red"}})
    with pytest.raises(ProviderAdapterError, match="media"):
        adapter.from_wire(
            {
                "model": "gemini-test",
                "input": [
                    {
                        "type": "user_input",
                        "content": [
                            {"type": "image", "mime_type": "image/png", "data": "opaque-base64"}
                        ],
                    }
                ],
            }
        )


def test_gemini_interactions_labels_require_explicit_safe_extension_policy() -> None:
    adapter = GeminiInteractionsAdapter(AdapterPolicy(safe_extension_fields=frozenset({"labels"})))
    request = adapter.from_wire(
        {"model": "gemini-test", "input": "hello", "labels": {"team": "synthetic"}}
    )
    assert adapter.to_wire(request)["labels"] == {"team": "synthetic"}


@pytest.mark.parametrize(
    ("adapter", "payload"),
    [
        (
            OpenAIResponsesAdapter(),
            {"model": "gpt-test", "input": "hello", "tools": [{"type": "web_search"}]},
        ),
        (
            AnthropicMessagesAdapter(),
            {
                "model": "claude-test",
                "max_tokens": 128,
                "messages": [{"role": "user", "content": "hello"}],
                "tools": [{"type": "web_search_20250305", "name": "web_search"}],
            },
        ),
        (
            GeminiGenerateContentAdapter(),
            {
                "model": "gemini-test",
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
                "tools": [{"googleSearch": {}}],
            },
        ),
        (
            GeminiInteractionsAdapter(),
            {"model": "gemini-test", "input": "hello", "tools": [{"type": "google_search"}]},
        ),
    ],
)
def test_remote_provider_tools_are_blocked_without_trusted_policy(
    adapter: object, payload: dict[str, object]
) -> None:
    with pytest.raises(ProviderAdapterError, match="remote tool"):
        adapter.from_wire(payload)  # type: ignore[attr-defined]


def test_remote_provider_tool_requires_and_preserves_explicit_trust() -> None:
    adapter = OpenAIResponsesAdapter(AdapterPolicy(allow_remote_tools=True))
    request = adapter.from_wire(
        {
            "model": "gpt-test",
            "input": "hello",
            "tools": [{"type": "web_search", "search_context_size": "low"}],
        }
    )
    assert adapter.to_wire(request)["tools"] == [
        {"type": "web_search", "search_context_size": "low"}
    ]


def test_openai_chat_unsupported_media_fails_closed() -> None:
    with pytest.raises(ProviderAdapterError, match="unsupported content block"):
        OpenAIChatCompletionsAdapter().from_wire(
            {
                "model": "gpt-test",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "input_audio",
                                "input_audio": {"format": "wav", "data": "opaque-base64"},
                            }
                        ],
                    }
                ],
            }
        )


def test_explicitly_safe_opaque_extension_round_trips() -> None:
    adapter = OpenAIResponsesAdapter(AdapterPolicy(safe_extension_fields=frozenset({"metadata"})))
    request = adapter.from_wire(
        {"model": "gpt-test", "input": "hello", "metadata": {"trace": "synthetic"}}
    )
    assert request.extensions[0].name == "metadata"
    assert adapter.to_wire(request)["metadata"] == {"trace": "synthetic"}


def test_provider_specific_extension_cannot_be_silently_dropped_cross_provider() -> None:
    ingress = OpenAIChatCompletionsAdapter(
        AdapterPolicy(safe_extension_fields=frozenset({"metadata"}))
    )
    request = ingress.from_wire(
        {
            "model": "gemini-test",
            "messages": [{"role": "user", "content": "hello"}],
            "metadata": {"trace": "synthetic"},
        }
    )

    with pytest.raises(ProviderAdapterError, match="cannot cross providers"):
        GeminiGenerateContentAdapter().to_wire(request)


def test_openai_chat_round_trip_preserves_tools_calls_results_and_schema() -> None:
    adapter = OpenAIChatCompletionsAdapter()
    wire = {
        "model": "gpt-test",
        "messages": [
            {"role": "system", "content": "Keep answers short"},
            {"role": "user", "content": "Weather in Paris"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {"name": "weather", "arguments": '{"city":"Paris"}'},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call-1", "content": '{"temperature":21}'},
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "weather",
                    "description": "Read weather",
                    "parameters": SCHEMA,
                    "strict": True,
                },
            }
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "forecast", "strict": True, "schema": SCHEMA},
        },
        "max_completion_tokens": 256,
        "stream": True,
    }
    request = adapter.from_wire(wire)
    outbound = adapter.to_wire(request)

    assert isinstance(request.turns[2].content[0], ToolCall)
    assert isinstance(request.turns[3].content[0], ToolResult)
    assert outbound["messages"][2]["tool_calls"][0]["function"]["arguments"] == ('{"city":"Paris"}')
    assert outbound["messages"][3]["tool_call_id"] == "call-1"
    assert outbound["response_format"]["json_schema"]["schema"] == SCHEMA
    assert outbound["store"] is False


def test_openai_responses_round_trip_preserves_item_semantics() -> None:
    adapter = OpenAIResponsesAdapter()
    wire = {
        "model": "gpt-test",
        "instructions": "Keep answers short",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "Weather in Paris"}],
            },
            {
                "type": "function_call",
                "call_id": "call-1",
                "name": "weather",
                "arguments": '{"city":"Paris"}',
            },
            {
                "type": "function_call_output",
                "call_id": "call-1",
                "output": '{"temperature":21}',
            },
        ],
        "tools": [
            {
                "type": "function",
                "name": "weather",
                "description": "Read weather",
                "parameters": SCHEMA,
                "strict": True,
            }
        ],
        "text": {
            "format": {"type": "json_schema", "name": "forecast", "strict": True, "schema": SCHEMA}
        },
        "max_output_tokens": 256,
    }
    request = adapter.from_wire(wire)
    outbound = adapter.to_wire(request)

    assert request.turns[0].role is CanonicalRole.SYSTEM
    assert isinstance(request.turns[2].content[0], ToolCall)
    assert isinstance(request.turns[3].content[0], ToolResult)
    assert outbound["input"][1]["type"] == "function_call"
    assert outbound["input"][2]["type"] == "function_call_output"
    assert outbound["text"]["format"]["schema"] == SCHEMA
    assert outbound["store"] is False


def test_anthropic_round_trip_preserves_tools_calls_results_and_schema() -> None:
    adapter = AnthropicMessagesAdapter()
    wire = {
        "model": "claude-test",
        "max_tokens": 256,
        "system": "Keep answers short",
        "messages": [
            {"role": "user", "content": "Weather in Paris"},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "call-1",
                        "name": "weather",
                        "input": {"city": "Paris"},
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "call-1",
                        "content": '{"temperature":21}',
                    }
                ],
            },
        ],
        "tools": [
            {
                "name": "weather",
                "description": "Read weather",
                "input_schema": SCHEMA,
                "strict": True,
            }
        ],
        "output_config": {"format": {"type": "json_schema", "schema": SCHEMA}},
        "stream": True,
    }
    request = adapter.from_wire(wire)
    outbound = adapter.to_wire(request)

    assert isinstance(request.turns[2].content[0], ToolCall)
    assert isinstance(request.turns[3].content[0], ToolResult)
    assert outbound["messages"][1]["content"][0]["type"] == "tool_use"
    assert outbound["messages"][2]["content"][0]["type"] == "tool_result"
    assert outbound["output_config"]["format"]["schema"] == SCHEMA


def test_gemini_generate_content_round_trip_preserves_function_parts() -> None:
    adapter = GeminiGenerateContentAdapter()
    wire = {
        "model": "gemini-test",
        "systemInstruction": {"parts": [{"text": "Keep answers short"}]},
        "contents": [
            {"role": "user", "parts": [{"text": "Weather in Paris"}]},
            {
                "role": "model",
                "parts": [
                    {"functionCall": {"id": "call-1", "name": "weather", "args": {"city": "Paris"}}}
                ],
            },
            {
                "role": "user",
                "parts": [
                    {
                        "functionResponse": {
                            "id": "call-1",
                            "name": "weather",
                            "response": {"temperature": 21},
                        }
                    }
                ],
            },
        ],
        "tools": [
            {
                "functionDeclarations": [
                    {"name": "weather", "description": "Read weather", "parameters": SCHEMA}
                ]
            }
        ],
        "generationConfig": {
            "maxOutputTokens": 256,
            "responseMimeType": "application/json",
            "responseSchema": SCHEMA,
        },
    }
    request = adapter.from_wire(wire)
    outbound = adapter.to_wire(request)

    assert isinstance(request.turns[2].content[0], ToolCall)
    assert isinstance(request.turns[3].content[0], ToolResult)
    assert outbound["contents"][1]["parts"][0]["functionCall"]["id"] == "call-1"
    assert outbound["contents"][2]["parts"][0]["functionResponse"]["id"] == "call-1"
    assert outbound["generationConfig"]["responseSchema"] == SCHEMA
    assert "store" not in outbound
    assert "model" not in outbound
    assert "stream" not in outbound
    assert adapter.target_for(request) == ("/v1beta/models/gemini-test:generateContent")


def test_experimental_gemini_interactions_round_trip_is_stateless_and_typed() -> None:
    adapter = GeminiInteractionsAdapter()
    assert adapter.experimental is True
    wire = {
        "model": "gemini-test",
        "system_instruction": "Keep answers short",
        "input": [
            {"type": "user_input", "content": [{"type": "text", "text": "Weather in Paris"}]},
            {
                "type": "function_call",
                "id": "call-1",
                "name": "weather",
                "arguments": {"city": "Paris"},
            },
            {
                "type": "function_result",
                "call_id": "call-1",
                "name": "weather",
                "result": [{"type": "text", "text": '{"temperature":21}'}],
            },
        ],
        "tools": [
            {
                "type": "function",
                "name": "weather",
                "description": "Read weather",
                "parameters": SCHEMA,
            }
        ],
        "response_format": {"type": "text", "mime_type": "application/json", "schema": SCHEMA},
        "generation_config": {"max_output_tokens": 256, "temperature": 0.2},
        "stream": True,
    }
    request = adapter.from_wire(wire)
    outbound = adapter.to_wire(request)

    assert isinstance(request.turns[2].content[0], ToolCall)
    assert isinstance(request.turns[3].content[0], ToolResult)
    assert outbound["input"][1]["type"] == "function_call"
    assert outbound["input"][2]["type"] == "function_result"
    assert outbound["response_format"]["schema"] == SCHEMA
    assert outbound["store"] is False


def test_openai_chat_stream_parser_covers_all_choices_and_tool_arguments() -> None:
    events = OpenAIChatCompletionsAdapter().parse_stream_event(
        {
            "choices": [
                {"index": 0, "delta": {"content": "first"}},
                {
                    "index": 1,
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "id": "call-1", "function": {"arguments": '{"city":'}}
                        ]
                    },
                    "finish_reason": "tool_calls",
                },
            ]
        }
    )
    assert isinstance(events[0], TextDelta)
    assert events[0].path[1] == 0
    assert isinstance(events[1], ToolArgumentsDelta)
    assert events[1].call_id == "call-1"
    assert isinstance(events[2], FinishEvent)


def test_openai_chat_stream_parser_handles_refusal_and_legacy_function_call() -> None:
    events = OpenAIChatCompletionsAdapter().parse_stream_event(
        {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "refusal": "cannot comply",
                        "function_call": {"name": "legacy", "arguments": '{"x":'},
                    },
                }
            ]
        }
    )
    assert isinstance(events[0], TextDelta)
    assert events[0].path[-1] == "refusal"
    assert isinstance(events[1], ToolArgumentsDelta)
    assert events[1].path[-2:] == ("function_call", "arguments")

    with pytest.raises(ProviderAdapterError, match="unknown stream delta"):
        OpenAIChatCompletionsAdapter().parse_stream_event(
            {"choices": [{"index": 0, "delta": {"new_opaque_field": "unsafe"}}]}
        )


def test_typed_stream_parsers_cover_structured_finish_and_error_events() -> None:
    responses = OpenAIResponsesAdapter()
    structured = responses.parse_stream_event(
        {
            "type": "response.output_text.delta",
            "output_index": 0,
            "content_index": 0,
            "delta": '{"answer":',
        },
        structured_output=True,
    )
    assert isinstance(structured[0], StructuredDataDelta)

    anthropic = AnthropicMessagesAdapter()
    arguments = anthropic.parse_stream_event(
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": '{"city":'},
        }
    )
    assert isinstance(arguments[0], ToolArgumentsDelta)

    interactions = GeminiInteractionsAdapter()
    finish = interactions.parse_stream_event(
        {"event_type": "interaction.completed", "interaction": {"status": "completed"}}
    )
    error = interactions.parse_stream_event(
        {"event_type": "error", "error": {"code": "bad_request", "message": "bad"}}
    )
    assert isinstance(finish[0], FinishEvent)
    assert isinstance(error[0], ErrorEvent)
