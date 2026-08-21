from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.chat.orchestrator import (
    PUBLIC_INVALID_CONVERSATION_ID_MESSAGE,
    PUBLIC_UNSANITIZED_MEDIA_MESSAGE,
    _assistant_message_from_response,
    _role_for_path,
)
from app.main import create_app
from app.proxy.llm_client import LLMClient, UpstreamResult


def _success_payload(content: str = "Safe local response") -> dict[str, Any]:
    return {
        "id": "chatcmpl-local",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
            }
        ],
    }


class RecordingUpstream:
    def __init__(self) -> None:
        self.complete_payloads: list[dict[str, Any]] = []
        self.stream_payloads: list[dict[str, Any]] = []

    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        self.complete_payloads.append(deepcopy(payload))
        return UpstreamResult(200, _success_payload())

    async def complete_stream(self, payload: dict[str, Any]):
        self.stream_payloads.append(deepcopy(payload))
        yield {
            "id": "chatcmpl-local-stream",
            "object": "chat.completion.chunk",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": "Safe streamed response"},
                    "finish_reason": None,
                }
            ],
        }
        yield {
            "id": "chatcmpl-local-stream",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }


class NonStreamingUpstream:
    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []

    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        self.payloads.append(deepcopy(payload))
        return UpstreamResult(200, _success_payload())


class ProviderErrorThenSuccessUpstream:
    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []

    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        self.payloads.append(deepcopy(payload))
        if len(self.payloads) == 1:
            return UpstreamResult(
                429,
                {
                    "error": {
                        "type": "provider_rate_limit",
                        "message": "Synthetic provider limit",
                    }
                },
            )
        return UpstreamResult(200, _success_payload())


class EmptyStreamUpstream(RecordingUpstream):
    async def complete_stream(self, payload: dict[str, Any]):
        self.stream_payloads.append(deepcopy(payload))
        yield {
            "id": "chatcmpl-empty-stream",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }


def _mock_llm_client(handler: httpx.MockTransport) -> LLMClient:
    return LLMClient(
        "https://provider.invalid/v1",
        "synthetic-test-key",
        transport=handler,
    )


def test_conversation_policy_block_returns_only_local_masked_preview(
    settings,
    playground_dir,
) -> None:
    upstream = RecordingUpstream()
    client = TestClient(
        create_app(settings, llm_client=upstream, playground_dir=playground_dir)
    )
    synthetic_secret = "sk-test-abcdefghijklmnop"

    response = client.post(
        "/playground/api/chat",
        json={
            "model": "test-model",
            "conversation_id": "blocked_conversation_1",
            "messages": [
                {"role": "user", "content": f"Review {synthetic_secret}"}
            ],
        },
    )

    assert response.status_code == 400
    body = response.json()
    assert body["response"]["error"]["type"] == "policy_block"
    assert body["trace"]["preview_only"] is True
    assert synthetic_secret not in str(body["trace"]["masked_request"])
    assert body["trace"]["upstream_response"] is None
    assert upstream.complete_payloads == []
    assert client.app.state.conversation_store.size() == 0


def test_conversation_reserved_token_injection_is_not_previewed_or_sent(
    settings,
    playground_dir,
) -> None:
    upstream = RecordingUpstream()
    client = TestClient(
        create_app(settings, llm_client=upstream, playground_dir=playground_dir)
    )

    response = client.post(
        "/playground/api/chat",
        json={
            "model": "test-model",
            "conversation_id": "reserved_token_conversation_1",
            "messages": [
                {
                    "role": "user",
                    "content": "Replay <MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>",
                }
            ],
        },
    )

    assert response.status_code == 400
    body = response.json()
    assert body["response"]["error"]["entities"] == ["RESERVED_TOKEN"]
    assert body["trace"]["masked_request"] is None
    assert upstream.complete_payloads == []
    assert client.app.state.conversation_store.size() == 0


def test_conversation_wire_guard_rejects_unknown_provider_field(settings) -> None:
    upstream = RecordingUpstream()
    client = TestClient(create_app(settings, llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": "wire_guard_conversation_1",
            "messages": [{"role": "user", "content": "Safe text"}],
            "input": "cross-provider field",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "wire_privacy_violation"
    assert upstream.complete_payloads == []
    assert client.app.state.conversation_store.size() == 0


def test_conversation_preview_for_unconfigured_provider_is_local_only(
    settings,
    playground_dir,
) -> None:
    unconfigured = replace(settings, llm_provider="openai", llm_api_key="")
    client = TestClient(create_app(unconfigured, playground_dir=playground_dir))

    response = client.post(
        "/playground/api/chat",
        json={
            "model": "test-model",
            "conversation_id": "preview_conversation_1",
            "messages": [{"role": "user", "content": "Contact user@example.com"}],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["response"]["preview_only"] is True
    assert body["trace"]["preview_reason"] == "provider_not_configured"
    assert body["trace"]["provider_ready"] is False
    assert "user@example.com" not in str(body["trace"]["masked_request"])
    assert body["trace"]["upstream_response"] is None


def test_conversation_upstream_transport_error_is_safe_and_clears_mapping(
    settings,
    playground_dir,
) -> None:
    requests: list[httpx.Request] = []

    def unavailable(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        raise httpx.ConnectError("synthetic offline provider", request=request)

    upstream = _mock_llm_client(httpx.MockTransport(unavailable))
    client = TestClient(
        create_app(settings, llm_client=upstream, playground_dir=playground_dir)
    )

    response = client.post(
        "/playground/api/chat",
        json={
            "model": "test-model",
            "conversation_id": "upstream_failure_1",
            "messages": [{"role": "user", "content": "Contact user@example.com"}],
        },
    )

    assert response.status_code == 502
    body = response.json()
    assert body["response"]["error"]["type"] == "upstream_unavailable"
    assert "user@example.com" not in response.text
    assert len(requests) == 1
    assert client.app.state.mapping_store.size() == 0


def test_conversation_provider_error_is_not_committed_to_history(settings) -> None:
    upstream = ProviderErrorThenSuccessUpstream()
    client = TestClient(create_app(settings, llm_client=upstream))
    conversation_id = "provider_error_history_1"

    first = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "First failed turn"}],
        },
    )
    second = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Second successful turn"}],
        },
    )

    assert first.status_code == 429
    assert second.status_code == 200
    assert len(upstream.payloads) == 2
    assert "First failed turn" not in str(upstream.payloads[1])
    assert "Second successful turn" in str(upstream.payloads[1])


def test_stream_rejects_unconfigured_provider_before_processing(settings) -> None:
    unconfigured = replace(settings, llm_provider="openai", llm_api_key="")
    client = TestClient(create_app(unconfigured))

    response = client.post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [], "stream": True},
    )

    assert response.status_code == 503
    assert response.json()["error"]["type"] == "provider_not_configured"


@pytest.mark.parametrize("stream", [False, True], ids=["nonstream", "stream"])
def test_playground_rejects_invalid_masking_mode(
    settings,
    playground_dir,
    stream: bool,
) -> None:
    client = TestClient(
        create_app(settings, llm_client=RecordingUpstream(), playground_dir=playground_dir)
    )

    response = client.post(
        "/playground/api/chat",
        json={
            "model": "test-model",
            "messages": [],
            "stream": stream,
            "masking_mode": "unknown-mode",
        },
    )

    assert response.status_code == 422
    payload = response.json()
    error = payload["response"]["error"] if not stream else payload["error"]
    assert error["type"] == "invalid_masking_mode"


@pytest.mark.parametrize("stream", [False, True], ids=["nonstream", "stream"])
def test_invalid_conversation_id_is_rejected(settings, stream: bool) -> None:
    client = TestClient(create_app(settings, llm_client=RecordingUpstream()))

    response = client.post(
        "/v1/chat/completions",
        headers={"X-MaskGate-Conversation-ID": "invalid!"},
        json={"model": "test-model", "messages": [], "stream": stream},
    )

    assert response.status_code == 422
    assert response.json()["error"] == {
        "message": PUBLIC_INVALID_CONVERSATION_ID_MESSAGE,
        "type": "invalid_conversation_id",
    }


def test_invalid_conversation_delete_uses_public_error(
    settings,
    playground_dir,
) -> None:
    client = TestClient(
        create_app(settings, llm_client=RecordingUpstream(), playground_dir=playground_dir)
    )

    response = client.delete("/playground/api/conversations/invalid!")

    assert response.status_code == 422
    assert response.json()["error"] == {
        "message": PUBLIC_INVALID_CONVERSATION_ID_MESSAGE,
        "type": "invalid_conversation_id",
    }


def test_stream_capacity_failure_does_not_contact_upstream(settings) -> None:
    upstream = RecordingUpstream()
    limited = replace(settings, conversation_max_count=1)
    client = TestClient(create_app(limited, llm_client=upstream))

    first = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": "capacity_holder_1",
            "messages": [{"role": "user", "content": "Hold capacity"}],
        },
    )
    second = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": "capacity_rejected_2",
            "messages": [{"role": "user", "content": "Do not send"}],
            "stream": True,
        },
    )

    assert first.status_code == 200
    assert second.status_code == 503
    assert second.json()["error"]["type"] == "conversation_capacity_exceeded"
    assert len(upstream.complete_payloads) == 1
    assert upstream.stream_payloads == []


def test_stream_rejects_conversation_mode_change(
    settings,
    playground_dir,
) -> None:
    upstream = RecordingUpstream()
    client = TestClient(
        create_app(settings, llm_client=upstream, playground_dir=playground_dir)
    )
    conversation_id = "stream_mode_change_1"

    first = client.post(
        "/playground/api/chat",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Start"}],
            "masking_mode": "placeholder",
        },
    )
    second = client.post(
        "/playground/api/chat",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Continue"}],
            "masking_mode": "surrogate",
            "stream": True,
        },
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error"]["type"] == "conversation_mode_mismatch"
    assert upstream.stream_payloads == []


@pytest.mark.parametrize(
    "conversation_id",
    [None, "media_conversation_1"],
    ids=["request", "conversation"],
)
def test_stream_media_block_is_fail_closed_and_releases_state(
    settings,
    conversation_id: str | None,
) -> None:
    upstream = RecordingUpstream()
    client = TestClient(create_app(settings, llm_client=upstream))
    payload: dict[str, Any] = {
        "model": "test-model",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Inspect locally"},
                    {
                        "type": "image_url",
                        "image_url": {"url": "data:image/png;base64,c3ludGhldGlj"},
                    },
                ],
            }
        ],
        "stream": True,
    }
    if conversation_id is not None:
        payload["conversation_id"] = conversation_id

    response = client.post("/v1/chat/completions", json=payload)

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "media_not_sanitized"
    assert response.json()["error"]["message"] == PUBLIC_UNSANITIZED_MEDIA_MESSAGE
    assert upstream.stream_payloads == []
    if conversation_id is not None:
        assert client.app.state.conversation_store.size() == 0


@pytest.mark.parametrize(
    "conversation_id",
    [None, "wire_conversation_1"],
    ids=["request", "conversation"],
)
def test_stream_wire_guard_rejects_unknown_provider_field(
    settings,
    conversation_id: str | None,
) -> None:
    upstream = RecordingUpstream()
    client = TestClient(create_app(settings, llm_client=upstream))
    payload: dict[str, Any] = {
        "model": "test-model",
        "messages": [{"role": "user", "content": "Safe text"}],
        "stream": True,
        "input": "cross-provider field",
    }
    if conversation_id is not None:
        payload["conversation_id"] = conversation_id

    response = client.post("/v1/chat/completions", json=payload)

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "wire_privacy_violation"
    assert upstream.stream_payloads == []
    if conversation_id is not None:
        assert client.app.state.conversation_store.size() == 0


@pytest.mark.parametrize(
    "conversation_id",
    [None, "policy_conversation_1"],
    ids=["request", "conversation"],
)
def test_stream_policy_block_never_contacts_provider(
    settings,
    conversation_id: str | None,
) -> None:
    upstream = RecordingUpstream()
    client = TestClient(create_app(settings, llm_client=upstream))
    payload: dict[str, Any] = {
        "model": "test-model",
        "messages": [
            {"role": "user", "content": "Use sk-test-abcdefghijklmnop"}
        ],
        "stream": True,
    }
    if conversation_id is not None:
        payload["conversation_id"] = conversation_id

    response = client.post("/v1/chat/completions", json=payload)

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "policy_block"
    assert upstream.stream_payloads == []
    if conversation_id is not None:
        assert client.app.state.conversation_store.size() == 0


def test_stream_without_provider_support_releases_conversation_lock(settings) -> None:
    upstream = NonStreamingUpstream()
    client = TestClient(create_app(settings, llm_client=upstream))
    conversation_id = "no_stream_support_1"

    stream_response = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Attempt stream"}],
            "stream": True,
        },
    )
    retry = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Retry normally"}],
        },
    )

    assert stream_response.status_code == 501
    assert stream_response.json()["error"]["type"] == "unsupported_feature"
    assert retry.status_code == 200
    assert len(upstream.payloads) == 1


def test_stream_upstream_error_is_safe_and_releases_conversation_lock(settings) -> None:
    def provider(request: httpx.Request) -> httpx.Response:
        if request.headers.get("accept") == "text/event-stream":
            return httpx.Response(502, json={"error": "synthetic unavailable"})
        return httpx.Response(200, json=_success_payload("Retry succeeded"))

    upstream = _mock_llm_client(httpx.MockTransport(provider))
    client = TestClient(create_app(settings, llm_client=upstream))
    conversation_id = "stream_upstream_error_1"

    stream_response = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Attempt stream"}],
            "stream": True,
        },
    )
    retry = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Retry normally"}],
        },
    )

    assert stream_response.status_code == 200
    assert "upstream_error" in stream_response.text
    assert "data: [DONE]" not in stream_response.text
    assert retry.status_code == 200
    assert client.app.state.mapping_store.size() == 0


def test_malformed_stream_event_becomes_safe_output_error(settings) -> None:
    malformed_sse = (
        'data: {"choices":[{"index":0,"delta":{"unknown":"value"}}]}\n\n'
        "data: [DONE]\n\n"
    )

    def provider(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=malformed_sse,
            headers={"content-type": "text/event-stream"},
        )

    client = TestClient(
        create_app(
            settings,
            llm_client=_mock_llm_client(httpx.MockTransport(provider)),
        )
    )

    response = client.post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [], "stream": True},
    )

    assert response.status_code == 200
    assert "upstream_invalid_stream" in response.text
    assert "data: [DONE]" not in response.text


@pytest.mark.parametrize(
    ("upstream", "expected_assistant"),
    [
        (RecordingUpstream(), "Safe streamed response"),
        (EmptyStreamUpstream(), None),
    ],
    ids=["text", "empty"],
)
def test_successful_conversation_stream_commits_only_safe_history(
    settings,
    upstream: RecordingUpstream,
    expected_assistant: str | None,
) -> None:
    client = TestClient(create_app(settings, llm_client=upstream))
    conversation_id = f"stream_history_{'text' if expected_assistant else 'empty'}"

    streamed = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "First turn"}],
            "stream": True,
        },
    )
    continued = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Second turn"}],
        },
    )

    assert streamed.status_code == 200
    assert "data: [DONE]" in streamed.text
    assert continued.status_code == 200
    history = upstream.complete_payloads[0]["messages"]
    assistant_contents = [
        item.get("content") for item in history if item.get("role") == "assistant"
    ]
    if expected_assistant is None:
        assert assistant_contents == []
    else:
        assert expected_assistant in assistant_contents


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"choices": []},
        {"choices": [None]},
        {"choices": [{"message": {"role": "user", "content": "ignored"}}]},
        {"choices": [{"message": {"role": "assistant"}}]},
    ],
)
def test_assistant_history_helper_rejects_unsupported_shapes(payload: Any) -> None:
    assert _assistant_message_from_response(payload) is None


def test_assistant_history_helper_preserves_structured_fields_by_value() -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "refusal": "Safe refusal",
                    "function_call": {"name": "lookup", "arguments": "{}"},
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": "{}"},
                        }
                    ],
                    "untrusted_extra": "must not be retained",
                }
            }
        ]
    }

    preserved = _assistant_message_from_response(payload)
    payload["choices"][0]["message"]["tool_calls"][0]["id"] = "mutated"

    assert preserved == {
        "role": "assistant",
        "content": None,
        "refusal": "Safe refusal",
        "function_call": {"name": "lookup", "arguments": "{}"},
        "tool_calls": [
            {
                "id": "call-1",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{}"},
            }
        ],
    }


@pytest.mark.parametrize(
    ("payload", "path", "expected"),
    [
        ({}, (), None),
        ({"messages": "invalid"}, ("messages", 0, "content"), None),
        ({"messages": []}, ("messages", 0, "content"), None),
        ({"messages": ["invalid"]}, ("messages", 0, "content"), None),
        ({"messages": [{"content": "safe"}]}, ("messages", 0, "content"), None),
        (
            {"messages": [{"role": "user", "content": "safe"}]},
            ("messages", 0, "content"),
            "user",
        ),
    ],
)
def test_role_lookup_fails_closed_for_malformed_message_paths(
    payload: dict[str, Any],
    path: tuple[str | int, ...],
    expected: str | None,
) -> None:
    assert _role_for_path(payload, path) == expected
