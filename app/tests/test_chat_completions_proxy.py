from __future__ import annotations

import json
import re
from dataclasses import replace

import httpx
from fastapi.testclient import TestClient

from app.identity import DefaultPrincipalResolver
from app.main import create_app
from app.privacy.policy import hash_public_value
from app.proxy.llm_client import LLMClient, UpstreamResult


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
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": f"Echo: {text}"}}
                ],
            },
        )


class FakeStreamingLLMClient:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    async def complete_stream(self, payload: dict):
        self.payloads.append(payload)
        user_message = [message for message in payload["messages"] if message["role"] == "user"][-1]
        token = re.search(r"<MG:[A-Z2-7]{26}>", user_message["content"])
        assert token is not None
        value = token.group(0)
        for content in (f"Echo: {value[:7]}", value[7:-1], f"{value[-1]} and done"):
            yield {
                "id": "chatcmpl_stream",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}],
            }


class ToolHistoryLLMClient:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    async def complete(self, payload: dict) -> UpstreamResult:
        self.payloads.append(payload)
        if len(self.payloads) == 1:
            user_text = payload["messages"][-1]["content"]
            token = re.search(r"<MG:[A-Z2-7]{26}>", user_text)
            assert token is not None
            return UpstreamResult(
                200,
                {
                    "id": "chatcmpl-tool-history",
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call-1",
                                        "type": "function",
                                        "function": {
                                            "name": "send_email",
                                            "arguments": json.dumps(
                                                {"recipient": token.group(0)}
                                            ),
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                },
            )
        return UpstreamResult(
            200,
            {
                "id": "chatcmpl-tool-history-2",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Done"},
                    }
                ],
            },
        )


def test_scoped_public_assertion_allows_only_the_matching_principal(
    settings, tmp_path
) -> None:
    first_key = "tenant-a-key"
    first_principal = DefaultPrincipalResolver(settings.application_id).resolve(
        authorization=f"Bearer {first_key}",
        client_host="testclient",
    )
    public_email = "press@example.org"
    policy_path = tmp_path / "policy-v2.yaml"
    policy_path.write_text(
        f"""
version: 2
defaults:
  action: BLOCK
  reason: unmatched_data
  obligations: [audit_decision]
rules:
  - id: tokenize-email
    priority: 10
    action: TOKENIZE
    reason: private_email
    obligations: [audit_decision]
    conditions:
      entity_types: [EMAIL]
public_data_assertions:
  - id: published-press-address
    entity_type: EMAIL
    value_sha256: {hash_public_value("EMAIL", public_email)}
    action: ALLOW
    reason: published_contact
    obligations: [audit_public_assertion]
    scope:
      tenants: [{first_principal.tenant_id}]
      applications: [{settings.application_id}]
      directions: [INPUT]
      providers: [mock]
      purposes: [{settings.default_purpose}]
    expires_at: 2099-01-01T00:00:00Z
    provenance: https://example.org/contact
""".strip(),
        encoding="utf-8",
    )
    upstream = FakeLLMClient()
    configured = replace(
        settings,
        api_keys=(first_key, "tenant-b-key"),
        policy_v2_file=policy_path,
    )
    client = TestClient(create_app(configured, llm_client=upstream))
    request = {
        "model": "gpt-test",
        "messages": [{"role": "user", "content": f"Contact {public_email}"}],
    }

    first = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {first_key}"},
        json=request,
    )
    second = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer tenant-b-key"},
        json=request,
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert public_email in str(upstream.payloads[0])
    assert public_email not in str(upstream.payloads[1])
    assert re.search(r"<MG:[A-Z2-7]{26}>", str(upstream.payloads[1]))


def test_conversation_history_preserves_safe_tool_calls_without_originals(settings) -> None:
    upstream = ToolHistoryLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))
    conversation_id = "tool_history_1234"

    first = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [
                {"role": "user", "content": "Email owner@example.com using the tool"}
            ],
        },
    )
    second = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Continue"}],
        },
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert "owner@example.com" in (
        first.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    )
    second_wire = upstream.payloads[1]
    assistant = next(
        message
        for message in second_wire["messages"]
        if message.get("role") == "assistant" and message.get("tool_calls")
    )
    arguments = assistant["tool_calls"][0]["function"]["arguments"]
    assert "owner@example.com" not in arguments
    assert re.search(r"<MG:[A-Z2-7]{26}>", arguments)


def test_health_and_end_to_end_rehydration(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))
    health = client.get("/health")
    assert health.json() == {"status": "ok"}
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in health.headers["content-security-policy"]
    assert health.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"

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
    assert re.search(
        r"<MG:[A-Z2-7]{26}>",
        upstream.payloads[0]["messages"][0]["content"],
    )
    assert "user@example.com" not in upstream.payloads[0]["messages"][0]["content"]
    assert client.app.state.mapping_store.size() == 0


def test_tool_call_arguments_are_masked_before_upstream(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "send_email",
                                "arguments": (
                                    '{"recipient":"private.user@example.com",'
                                    '"note":"Send the receipt"}'
                                ),
                            },
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": "Continue after the tool call.",
                },
            ],
        },
    )

    assert response.status_code == 200
    outbound = str(upstream.payloads[0])
    assert "private.user@example.com" not in outbound
    assert re.search(r"<MG:[A-Z2-7]{26}>", outbound)


def test_nested_extension_text_is_masked_but_protocol_fields_are_preserved(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Continue."}],
            "user": "metadata.user@example.com",
            "metadata": {
                "customer": {
                    "contact": "metadata.user@example.com",
                    "key.user@example.com": "also private",
                }
            },
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "send_email",
                        "description": "Send a receipt to metadata.user@example.com",
                    },
                }
            ],
        },
    )

    assert response.status_code == 200
    outbound = upstream.payloads[0]
    assert "metadata.user@example.com" not in str(outbound)
    assert "key.user@example.com" not in str(outbound)
    assert outbound["model"] == "gpt-test"
    assert outbound["tools"][0]["type"] == "function"
    assert outbound["tools"][0]["function"]["name"] == "send_email"


def test_protocol_identifiers_with_pii_fail_closed_before_upstream(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "private.model@example.com",
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "policy_block"
    assert response.json()["error"]["entities"] == ["PROTOCOL_FIELD"]
    assert upstream.payloads == []


def test_blocked_protocol_identifier_is_not_written_to_logs(settings, capsys) -> None:
    sensitive_model = "private.logging@example.com"
    client = TestClient(create_app(replace(settings, log_level="INFO"), llm_client=FakeLLMClient()))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": sensitive_model,
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )

    assert response.status_code == 400
    log_output = capsys.readouterr().out
    assert "request_completed" in log_output
    assert sensitive_model not in log_output
    assert f'"model_length":{len(sensitive_model)}' in log_output


def test_serialized_http_body_contains_only_masked_values(settings) -> None:
    captured: dict[str, object] = {}

    def provider(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        captured["authorization"] = request.headers.get("authorization")
        outbound = request.content.decode("utf-8")
        token = re.search(r"<MG:[A-Z2-7]{26}>", outbound)
        assert token is not None
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl_transport",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"Contact {token.group(0)}",
                        },
                    }
                ],
            },
        )

    upstream = LLMClient(
        "https://provider.invalid/v1",
        "provider-test-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(settings, llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer untrusted-client-token"},
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Email body.user@example.com"}],
            "metadata": {
                "contact": "body.user@example.com",
                "body.key@example.com": "private key name",
            },
        },
    )

    assert response.status_code == 200
    body = json.loads(bytes(captured["body"]))
    assert "body.user@example.com" not in json.dumps(body)
    assert "body.key@example.com" not in json.dumps(body)
    assert re.search(r"<MG:[A-Z2-7]{26}>", json.dumps(body))
    assert captured["authorization"] == "Bearer provider-test-key"
    assert response.json()["choices"][0]["message"]["content"] == "Contact body.user@example.com"


def test_configured_proxy_auth_rejects_invalid_bearer_before_upstream(settings) -> None:
    upstream = FakeLLMClient()
    secured = replace(settings, api_keys=("maskgate-test-key",))
    client = TestClient(create_app(secured, llm_client=upstream))
    payload = {
        "model": "gpt-test",
        "messages": [{"role": "user", "content": "Hello"}],
    }

    missing = client.post("/v1/chat/completions", json=payload)
    invalid = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer wrong-key"},
        json=payload,
    )
    allowed = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer maskgate-test-key"},
        json=payload,
    )

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert missing.headers["x-content-type-options"] == "nosniff"
    assert missing.headers["x-frame-options"] == "DENY"
    assert allowed.status_code == 200
    assert len(upstream.payloads) == 1


def test_production_disables_interactive_api_docs(settings) -> None:
    production = replace(
        settings,
        app_env="production",
        require_auth=True,
        api_keys=("maskgate-test-key",),
        enable_debug_endpoints=False,
        enable_playground=False,
    )
    client = TestClient(create_app(production, llm_client=FakeLLMClient()))

    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_untrusted_host_is_rejected(settings) -> None:
    hosted = replace(settings, trusted_hosts=("maskgate.local", "testserver"))
    client = TestClient(create_app(hosted, llm_client=FakeLLMClient()))

    assert client.get("/health", headers={"Host": "maskgate.local"}).status_code == 200
    assert client.get("/health", headers={"Host": "evil.example"}).status_code == 400


def test_oversized_request_is_rejected_before_upstream(settings) -> None:
    upstream = FakeLLMClient()
    limited = replace(settings, max_request_body_bytes=256)
    client = TestClient(create_app(limited, llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "x" * 1_000}],
        },
    )

    assert response.status_code == 413
    assert response.json()["error"]["type"] == "request_too_large"
    assert upstream.payloads == []


def test_rate_limit_stops_excess_requests_before_upstream(settings) -> None:
    upstream = FakeLLMClient()
    limited = replace(
        settings,
        rate_limit_requests=1,
        rate_limit_window_seconds=60,
    )
    client = TestClient(create_app(limited, llm_client=upstream))
    payload = {
        "model": "gpt-test",
        "messages": [{"role": "user", "content": "Hello"}],
    }

    allowed = client.post("/v1/chat/completions", json=payload)
    rejected = client.post("/v1/chat/completions", json=payload)

    assert allowed.status_code == 200
    assert rejected.status_code == 429
    assert rejected.json()["error"]["type"] == "rate_limit_exceeded"
    assert rejected.headers["retry-after"] == "60"
    assert len(upstream.payloads) == 1


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


def test_reserved_token_injection_blocks_before_upstream(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [
                {"role": "user", "content": "Replay <MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"}
            ],
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["entities"] == ["RESERVED_TOKEN"]
    assert upstream.payloads == []


def test_playground_preview_does_not_call_unconfigured_provider(settings, playground_dir) -> None:
    unconfigured = replace(settings, llm_provider="openai", llm_api_key="")
    client = TestClient(create_app(unconfigured, playground_dir=playground_dir))
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
    readiness = client.get("/health/ready")
    assert readiness.status_code == 503
    assert readiness.json() == {"status": "not_ready", "provider_ready": False}


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


def test_blocked_playground_request_shows_preview_but_is_not_sent(settings, playground_dir) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream, playground_dir=playground_dir))
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
    assert (
        "sk-test-abcdefghijklmnop" not in body["trace"]["masked_request"]["messages"][0]["content"]
    )
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
    assert "<MG:" not in response.text
    assert "user@example.com" not in str(upstream.payloads[0])


def test_debug_endpoints(settings) -> None:
    client = TestClient(create_app(settings, llm_client=FakeLLMClient()))
    analyzed = client.post("/debug/analyze", json={"text": "user@example.com"})
    assert analyzed.status_code == 200
    assert analyzed.json()["entities"][0]["type"] == "EMAIL"

    masked = client.post("/debug/mask", json={"text": "user@example.com", "mode": "placeholder"})
    assert masked.status_code == 200
    assert re.fullmatch(
        r"<MG:[A-Z2-7]{26}>",
        masked.json()["masked_text"],
    )


def test_playground_is_served_and_exposes_safe_trace(settings, playground_dir) -> None:
    client = TestClient(
        create_app(settings, llm_client=FakeLLMClient(), playground_dir=playground_dir)
    )
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


def test_public_api_cannot_override_operator_masking_mode(settings) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Write to user@example.com"}],
            "masking_mode": "surrogate",
        },
    )

    assert response.status_code == 200
    provider_text = str(upstream.payloads[0])
    assert re.search(r"<MG:[A-Z2-7]{26}>", provider_text)
    assert "@example.test" not in provider_text


def test_conversation_rejects_masking_mode_changes(settings, playground_dir) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream, playground_dir=playground_dir))
    headers = {"X-MaskGate-Conversation-ID": "conversation-mode-test"}

    first = client.post(
        "/playground/api/chat",
        headers=headers,
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Write to user@example.com"}],
            "masking_mode": "placeholder",
        },
    )
    second = client.post(
        "/playground/api/chat",
        headers=headers,
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Continue"}],
            "masking_mode": "surrogate",
        },
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["response"]["error"]["type"] == "conversation_mode_mismatch"


def test_conversation_vault_keeps_masked_history_and_reuses_mapping(
    settings, playground_dir
) -> None:
    upstream = FakeLLMClient()
    client = TestClient(create_app(settings, llm_client=upstream, playground_dir=playground_dir))
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
    assert any(
        re.fullmatch(r"Write to <MG:[A-Z2-7]{26}>", message.get("content", ""))
        for message in outbound_messages
    )
    assert all("user@example.com" not in str(message) for message in outbound_messages)
    assert (
        second.json()["choices"][0]["message"]["content"] == "Echo: Now continue the conversation."
    )
    assert client.app.state.conversation_store.size() == 1

    cleared = client.delete(f"/playground/api/conversations/{conversation_id}")
    assert cleared.status_code == 200
    assert client.app.state.conversation_store.size() == 0


def test_conversation_vault_is_isolated_by_hashed_proxy_identity(settings) -> None:
    upstream = FakeLLMClient()
    secured = replace(settings, api_keys=("tenant-a-key", "tenant-b-key"))
    client = TestClient(create_app(secured, llm_client=upstream))
    conversation_id = "shared_name_1234"

    first = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer tenant-a-key"},
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Email owner.a@example.com"}],
        },
    )
    second = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer tenant-b-key"},
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Continue separately"}],
        },
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert "owner.a@example.com" not in str(upstream.payloads[1])
    assert not any(
        re.search(r"<MG:[A-Z2-7]{26}>", str(message))
        for message in upstream.payloads[1]["messages"]
    )
    assert client.app.state.conversation_store.size() == 2


def test_conversation_store_rejects_new_sessions_when_capacity_is_full(settings) -> None:
    upstream = FakeLLMClient()
    limited = replace(settings, conversation_max_count=1)
    client = TestClient(create_app(limited, llm_client=upstream))

    first = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "conversation_id": "capacity_one_1",
            "messages": [{"role": "user", "content": "First"}],
        },
    )
    second = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "conversation_id": "capacity_two_2",
            "messages": [{"role": "user", "content": "Second"}],
        },
    )

    assert first.status_code == 200
    assert second.status_code == 503
    assert second.json()["error"]["type"] == "conversation_capacity_exceeded"
    assert len(upstream.payloads) == 1
