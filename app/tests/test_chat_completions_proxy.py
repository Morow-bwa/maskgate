from __future__ import annotations

from dataclasses import replace

from fastapi.testclient import TestClient

from app.main import create_app
from app.proxy.llm_client import UpstreamResult


class FakeLLMClient:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    async def complete(self, payload: dict) -> UpstreamResult:
        self.payloads.append(payload)
        user_message = [message for message in payload["messages"] if message["role"] == "user"][-1]
        text = user_message["content"]
        return UpstreamResult(
            200,
            {
                "id": "chatcmpl_mock",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": f"Echo: {text}"}}],
            },
        )


class FakeStreamingLLMClient:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    async def complete_stream(self, payload: dict):
        self.payloads.append(payload)
        for content in ("Echo: <EMAIL", "_1", "> and done"):
            yield {
                "id": "chatcmpl_stream",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}],
            }


def test_health_and_end_to_end_rehydration(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))
    health = client.get("/health")
    assert health.json() == {"status": "ok"}
    assert health.headers["x-content-type-options"] == "nosniff"

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Write to user@example.com"}],
            "temperature": 0.7,
        },
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "user@example.com" in response.json()["choices"][0]["message"]["content"]
    assert response.json()["choices"][0]["message"]["content"] == "Echo: Write to user@example.com"
    assert upstream.payloads[0]["messages"][0]["role"] == "system"
    assert "<EMAIL_1>" in upstream.payloads[0]["messages"][0]["content"]
    assert "user@example.com" not in upstream.payloads[0]["messages"][0]["content"]
    assert client.app.state.mapping_store.size() == 0


def test_api_key_policy_blocks_before_upstream(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Use sk-test-abcdefghijklmnop"}],
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["type"] == "policy_block"
    assert response.json()["error"]["entities"] == ["API_KEY"]
    assert upstream.payloads == []


def test_playground_preview_does_not_call_unconfigured_provider(settings) -> None:
    unconfigured = replace(settings, llm_provider="openai", llm_api_key="")
    client = TestClient(create_app(unconfigured))
    payload = {
        "model": "gpt-test",
        "messages": [{"role": "user", "content": "Reply to user@example.com"}],
    }

    playground_response = client.post("/playground/api/chat", json=payload)
    assert playground_response.status_code == 200
    playground_body = playground_response.json()
    assert playground_body["response"]["choices"] == []
    assert playground_body["trace"]["preview_only"] is True
    assert playground_body["trace"]["preview_reason"] == "provider_not_configured"
    assert playground_body["trace"]["upstream_response"] is None
    assert "user@example.com" not in str(playground_body["trace"]["masked_request"])

    api_response = client.post("/v1/chat/completions", json=payload)
    assert api_response.status_code == 503
    assert api_response.json()["error"]["type"] == "provider_not_configured"


def test_unsanitized_image_is_blocked_before_upstream(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What is on this screen?"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,raw"}},
                    ],
                }
            ],
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["type"] == "media_not_sanitized"
    assert upstream.payloads == []


def test_blocked_playground_request_shows_preview_but_is_not_sent(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))
    response = client.post(
        "/playground/api/chat",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Use sk-test-abcdefghijklmnop"}],
        },
    )
    assert response.status_code == 400
    body = response.json()
    assert body["trace"]["preview_only"] is True
    assert "sk-test-abcdefghijklmnop" not in body["trace"]["masked_request"]["messages"][0]["content"]
    assert body["trace"]["upstream_response"] is None
    assert upstream.payloads == []


def test_streaming_requires_upstream_stream_support(settings) -> None:
    client = TestClient(create_app(settings, llm_client=FakeLLMClient()))
    response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-test", "messages": [], "stream": True},
    )
    assert response.status_code == 501
    assert response.json()["error"]["type"] == "unsupported_feature"


def test_streaming_rehydrates_split_placeholder(settings) -> None:
    upstream = FakeStreamingLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Write to user@example.com"}],
            "stream": True,
        },
    )
    assert response.status_code == 200
    assert "data: [DONE]" in response.text
    assert "user@example.com" in response.text
    assert "<EMAIL_1" not in response.text
    assert "user@example.com" not in str(upstream.payloads[0])


def test_debug_endpoints(settings) -> None:
    client = TestClient(create_app(settings, llm_client=FakeLLMClient()))
    analyzed = client.post("/debug/analyze", json={"text": "user@example.com"})
    assert analyzed.status_code == 200
    assert analyzed.json()["entities"][0]["type"] == "EMAIL"

    masked = client.post("/debug/mask", json={"text": "user@example.com", "mode": "placeholder"})
    assert masked.status_code == 200
    assert masked.json()["masked_text"] == "<EMAIL_1>"


def test_playground_is_served_and_exposes_safe_trace(settings) -> None:
    client = TestClient(create_app(settings, llm_client=FakeLLMClient()))
    page = client.get("/playground")
    assert page.status_code == 200
    assert "MaskGate" in page.text
    assert client.get("/playground/config").json()["provider"] == "mock"

    response = client.post(
        "/playground/api/chat",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Reply to user@example.com"}],
            "masking_mode": "surrogate",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["response"]["choices"][0]["message"]["content"] == "Echo: Reply to user@example.com"
    assert body["trace"]["masking_mode"] == "surrogate"
    assert "user@example.com" not in body["trace"]["masked_request"]["messages"][0]["content"]
    provider_text = body["trace"]["upstream_response"]["choices"][0]["message"]["content"]
    assert "user@example.com" not in provider_text
    assert "@example.test" in provider_text


def test_conversation_vault_keeps_masked_history_and_reuses_mapping(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))
    conversation_id = "conv_test_1234"

    first = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Write to user@example.com"}],
        },
    )
    assert first.status_code == 200
    assert first.json()["choices"][0]["message"]["content"] == "Echo: Write to user@example.com"

    second = client.post(
        "/v1/chat/completions",
        headers={"X-MaskGate-Conversation-ID": conversation_id},
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Now continue the conversation."}],
        },
    )
    assert second.status_code == 200
    outbound_messages = upstream.payloads[1]["messages"]
    assert any(message.get("content") == "Write to <EMAIL_1>" for message in outbound_messages)
    assert all("user@example.com" not in str(message) for message in outbound_messages)
    assert second.json()["choices"][0]["message"]["content"] == "Echo: Now continue the conversation."
    assert client.app.state.conversation_store.size() == 1

    cleared = client.delete(f"/playground/api/conversations/{conversation_id}")
    assert cleared.status_code == 200
    assert client.app.state.conversation_store.size() == 0
