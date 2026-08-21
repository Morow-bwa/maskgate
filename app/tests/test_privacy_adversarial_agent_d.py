from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import replace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.logging_config import SafeJsonFormatter
from app.main import create_app
from app.masking.anonymizer import MaskingSession
from app.masking.detector import Entity
from app.observability import PrivacyMetrics
from app.policies.policy_engine import PolicyEngine
from app.privacy.detection import DetectorEnsemble
from app.privacy.models import DetectorProfile
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.pipeline import PrivacyPipeline
from app.privacy.vault import (
    InMemoryVault,
    MappingItem,
    VaultBudget,
    VaultCapacityExceeded,
)
from app.privacy.wire import FinalWirePrivacyGuard, WirePrivacyViolation
from app.providers import AdapterPolicy, OpenAIChatCompletionsAdapter
from app.proxy.llm_client import LLMClient, LLMUpstreamError
from app.storage.conversation_store import InMemoryConversationStore

RAW_PROVIDER_VALUES = (
    ("IBAN", "GB82 WEST 1234 5698 7654 32"),
    ("SNILS", "112-233-445 95"),
    ("PASSPORT", "паспорт 4510 123456"),
    (
        "JWT",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
    ),
    ("IP_ADDRESS", "2001:db8:85a3::8a2e:370:7334"),
)

TOKEN_PATTERN = re.compile(r"<MG:[A-Z2-7]{26}>")


class _SafeTargetUpstream:
    @staticmethod
    def prepare_request(
        payload: dict[str, Any], *, stream: bool = False
    ) -> tuple[str, str, dict[str, Any]]:
        return "openai-chat", "/chat/completions", payload


class _PostSerializationInjectingAdapter:
    name = "openai-chat"

    def __init__(self, value: str) -> None:
        self.value = value

    def to_wire(self, canonical: object) -> dict[str, Any]:
        return {
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "safe synthetic prompt"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "agent_d_lookup",
                        "description": self.value,
                        "parameters": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}},
                        },
                    },
                }
            ],
        }


def _privacy_components() -> tuple[DetectorEnsemble, FinalWirePrivacyGuard, OutputPrivacyGuard]:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
    return detector, FinalWirePrivacyGuard(detector), OutputPrivacyGuard(detector)


def _provider_response(request: httpx.Request, content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-agent-d",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        },
        request=request,
    )


def test_provider_percent_encoded_email_is_not_returned_to_client(settings) -> None:
    encoded_email = "novel%2Eowner%40example%2Enet"

    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-agent-d-encoded-output",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": encoded_email},
                        "finish_reason": "stop",
                    }
                ],
            },
            request=request,
        )

    upstream = LLMClient(
        "https://provider.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Safe synthetic prompt"}],
        },
    )

    assert response.status_code == 200
    assert encoded_email not in response.text


def test_provider_exception_message_is_not_returned_to_client(settings) -> None:
    provider_email = "exception.owner@example.net"

    class HostileProvider:
        async def complete(self, payload: object) -> object:
            raise LLMUpstreamError("upstream_rejected", f"Rejected {provider_email}")

    client = TestClient(
        create_app(
            replace(settings, llm_provider="openai"),
            llm_client=HostileProvider(),
        )
    )

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Safe synthetic prompt"}],
        },
    )

    assert response.status_code == 502
    assert provider_email not in response.text


def test_provider_unicode_escaped_email_is_not_returned_to_client(settings) -> None:
    escaped_email = r"novel\u0040example\u002enet"

    def provider(request: httpx.Request) -> httpx.Response:
        return _provider_response(request, escaped_email)

    upstream = LLMClient(
        "https://provider.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Safe synthetic prompt"}],
        },
    )

    assert response.status_code == 200
    assert escaped_email not in response.text


@pytest.mark.parametrize(
    "encoded_email",
    [
        base64.b64encode(b"base64.owner@example.net").decode("ascii"),
        b"hex.owner@example.net".hex(),
    ],
)
def test_provider_opaque_encoded_email_is_not_returned_to_client(
    settings,
    encoded_email: str,
) -> None:
    def provider(request: httpx.Request) -> httpx.Response:
        return _provider_response(request, encoded_email)

    upstream = LLMClient(
        "https://provider.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Safe synthetic prompt"}],
        },
    )

    assert response.status_code == 200
    assert encoded_email not in response.text


@pytest.mark.parametrize(
    ("injected", "expected_error"),
    [
        ("wire%2Eowner%40example%2Enet", "encoded EMAIL"),
        (r"wire\u0040example\u002enet", "encoded EMAIL"),
        (
            base64.b64encode(b"wire.owner@example.net").decode("ascii"),
            "unsupported encoded content",
        ),
        (b"wire.owner@example.net".hex(), "unsupported encoded content"),
    ],
)
def test_malicious_adapter_encoded_post_serialization_injection_is_rejected(
    settings,
    injected: str,
    expected_error: str,
) -> None:
    _, wire_guard, output_guard = _privacy_components()
    pipeline = PrivacyPipeline(
        _SafeTargetUpstream(),
        "openai",
        wire_guard,
        output_guard,
        ingress_adapter=OpenAIChatCompletionsAdapter(AdapterPolicy()),
        egress_adapter=_PostSerializationInjectingAdapter(injected),
    )

    with pytest.raises(WirePrivacyViolation, match=expected_error):
        pipeline.prepare(
            {
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "safe synthetic prompt"}],
            },
            MaskingSession("placeholder", PolicyEngine(settings.policy_file)),
            [],
        )


@pytest.mark.parametrize(
    "encoded_value",
    [
        "tool%2Eowner%40example%2Enet",
        r"tool\u0040example\u002enet",
        base64.b64encode(b"tool.owner@example.net").decode("ascii"),
        b"tool.owner@example.net".hex(),
    ],
)
def test_encoded_provider_pii_is_redacted_inside_tool_arguments(
    encoded_value: str,
) -> None:
    _, _, output_guard = _privacy_components()
    arguments = json.dumps({"value": encoded_value}, ensure_ascii=False)

    guarded = output_guard.process(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_agent_d_encoded",
                                "type": "function",
                                "function": {
                                    "name": "agent_d_lookup",
                                    "arguments": arguments,
                                },
                            }
                        ],
                    }
                }
            ]
        },
        [],
    )

    safe_arguments = guarded["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert isinstance(safe_arguments, str)
    if safe_arguments.startswith("{"):
        assert json.loads(safe_arguments)["value"] != encoded_value
    assert "[REDACTED_PROVIDER_ENCODED" in safe_arguments


@pytest.mark.parametrize(("expected_type", "injected"), RAW_PROVIDER_VALUES)
def test_malicious_adapter_post_serialization_injection_is_rejected(
    settings,
    expected_type: str,
    injected: str,
) -> None:
    _, wire_guard, output_guard = _privacy_components()
    pipeline = PrivacyPipeline(
        _SafeTargetUpstream(),
        "openai",
        wire_guard,
        output_guard,
        ingress_adapter=OpenAIChatCompletionsAdapter(AdapterPolicy()),
        egress_adapter=_PostSerializationInjectingAdapter(injected),
    )
    session = MaskingSession("placeholder", PolicyEngine(settings.policy_file))

    with pytest.raises(WirePrivacyViolation, match=expected_type):
        pipeline.prepare(
            {
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "safe synthetic prompt"}],
            },
            session,
            [],
        )


@pytest.mark.parametrize(("expected_type", "provider_value"), RAW_PROVIDER_VALUES)
def test_new_raw_provider_pii_is_redacted_in_non_stream_output(
    expected_type: str,
    provider_value: str,
) -> None:
    _, _, output_guard = _privacy_components()

    guarded = output_guard.process(
        {"choices": [{"message": {"role": "assistant", "content": provider_value}}]},
        [],
    )

    assert provider_value not in str(guarded)
    assert f"[REDACTED_PROVIDER_{expected_type}]" in str(guarded)


@pytest.mark.parametrize(("expected_type", "provider_value"), RAW_PROVIDER_VALUES)
def test_new_raw_provider_pii_is_redacted_in_tool_arguments(
    expected_type: str,
    provider_value: str,
) -> None:
    _, _, output_guard = _privacy_components()
    arguments = json.dumps({"value": provider_value}, ensure_ascii=False)

    guarded = output_guard.process(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_agent_d",
                                "type": "function",
                                "function": {
                                    "name": "agent_d_lookup",
                                    "arguments": arguments,
                                },
                            }
                        ],
                    }
                }
            ]
        },
        [],
    )

    assert provider_value not in str(guarded)
    assert f"[REDACTED_PROVIDER_{expected_type}]" in str(guarded)


def test_stream_mode_mismatch_fails_before_provider_serialization(settings) -> None:
    _, wire_guard, output_guard = _privacy_components()
    adapter = OpenAIChatCompletionsAdapter(AdapterPolicy())
    pipeline = PrivacyPipeline(
        _SafeTargetUpstream(),
        "openai",
        wire_guard,
        output_guard,
        ingress_adapter=adapter,
        egress_adapter=adapter,
    )

    with pytest.raises(WirePrivacyViolation, match="provider adapter rejected"):
        pipeline.prepare(
            {
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "safe synthetic prompt"}],
                "stream": True,
            },
            MaskingSession("placeholder", PolicyEngine(settings.policy_file)),
            [],
            stream=False,
        )


def test_checked_wire_bytes_cannot_be_changed_by_post_check_mutation() -> None:
    _, wire_guard, _ = _privacy_components()
    payload = {
        "model": "gpt-test",
        "messages": [{"role": "user", "content": "safe synthetic prompt"}],
    }
    checked = wire_guard.check(provider="openai-chat", payload=payload)
    original_body = checked.body

    payload["messages"][0]["content"] = "post.check.owner@example.net"
    parsed_copy = checked.payload
    parsed_copy["messages"][0]["content"] = "copy.owner@example.net"

    assert checked.body == original_body
    assert b"post.check.owner@example.net" not in checked.body
    assert b"copy.owner@example.net" not in checked.body


@pytest.mark.parametrize("scope", ["tenant", "conversation"])
def test_opaque_tokens_do_not_restore_across_state_scopes(settings, scope: str) -> None:
    policy = PolicyEngine(settings.policy_file)
    store = InMemoryConversationStore(ttl_seconds=60)
    if scope == "tenant":
        first_key = ("conversation-shared", "tenant-a")
        second_key = ("conversation-shared", "tenant-b")
    else:
        first_key = ("conversation-first", "tenant-shared")
        second_key = ("conversation-second", "tenant-shared")
    first_state = store.get_or_create(
        *first_key,
        lambda: MaskingSession("placeholder", policy),
    )
    second_state = store.get_or_create(
        *second_key,
        lambda: MaskingSession("placeholder", policy),
    )
    first_original = f"first.{scope}@example.net"
    second_original = f"second.{scope}@example.net"
    first_entity = Entity("EMAIL", first_original, 0, len(first_original))
    second_entity = Entity("EMAIL", second_original, 0, len(second_original))
    first_token = first_state.session.mask_text(first_original, [first_entity])
    second_state.session.mask_text(second_original, [second_entity])
    _, _, output_guard = _privacy_components()

    guarded = output_guard.process(
        {"choices": [{"message": {"content": first_token}}]},
        second_state.session.items,
    )

    assert first_original not in str(guarded)
    assert second_original not in str(guarded)
    assert first_token not in str(guarded)
    assert "[REDACTED_PROVIDER_TOKEN]" in str(guarded)


def test_opaque_token_format_and_uniqueness_across_thousands(settings) -> None:
    session = MaskingSession("placeholder", PolicyEngine(settings.policy_file))
    tokens: set[str] = set()

    for index in range(4_096):
        original = f"agent-d-{index}@example.net"
        token = session.mask_text(
            original,
            [Entity("EMAIL", original, 0, len(original))],
        )
        assert TOKEN_PATTERN.fullmatch(token)
        tokens.add(token)

    assert len(tokens) == 4_096


def test_opaque_token_generation_retries_a_local_collision(settings, monkeypatch) -> None:
    generated = iter([b"\x00" * 16, b"\x00" * 16, b"\x01" * 16])
    monkeypatch.setattr(
        "app.masking.anonymizer.secrets.token_bytes",
        lambda size: next(generated),
    )
    session = MaskingSession("placeholder", PolicyEngine(settings.policy_file))
    originals = ("collision-first@example.net", "collision-second@example.net")

    tokens = [
        session.mask_text(
            original,
            [Entity("EMAIL", original, 0, len(original))],
        )
        for original in originals
    ]

    assert len(set(tokens)) == 2
    assert all(TOKEN_PATTERN.fullmatch(token) for token in tokens)


def test_vault_enforces_mapping_budget_at_five_thousand() -> None:
    vault = InMemoryVault(VaultBudget(max_mappings=5_000, max_sensitive_bytes=1_000_000))

    for index in range(5_000):
        vault.add(MappingItem("EMAIL", f"value-{index}", f"token-{index}"))

    with pytest.raises(VaultCapacityExceeded):
        vault.add(MappingItem("EMAIL", "one-too-many", "token-overflow"))
    assert len(vault.items) == 5_000


def test_vault_repeated_mapping_does_not_consume_additional_budget() -> None:
    vault = InMemoryVault(VaultBudget(max_mappings=1, max_sensitive_bytes=1_024))
    item = MappingItem("EMAIL", "repeated@example.net", "token-repeated")

    for _ in range(10_000):
        vault.add(item)

    assert vault.items == (item,)


def test_vault_enforces_sensitive_byte_budget() -> None:
    vault = InMemoryVault(VaultBudget(max_mappings=10, max_sensitive_bytes=1_024))
    vault.add(MappingItem("TEXT", "a" * 1_024, "token-a"))

    with pytest.raises(VaultCapacityExceeded):
        vault.add(MappingItem("TEXT", "b", "token-b"))


def test_conversation_character_budget_is_a_hard_retention_bound(settings) -> None:
    store = InMemoryConversationStore(ttl_seconds=60, max_chars=1_000)
    session = MaskingSession("placeholder", PolicyEngine(settings.policy_file))
    state = store.get_or_create("conversation-agent-d", "tenant-agent-d", lambda: session)

    store.commit(state, session, [{"role": "user", "content": "x" * 1_500}])

    retained_chars = sum(len(str(message.get("content", ""))) for message in state.messages)
    assert retained_chars <= 1_000


def test_logs_and_metrics_do_not_serialize_exception_original() -> None:
    original = "observability.owner@example.net"
    try:
        raise ValueError(original)
    except ValueError:
        record = logging.LogRecord(
            "maskgate",
            logging.ERROR,
            __file__,
            1,
            "request_completed",
            (),
            __import__("sys").exc_info(),
        )
    record.error_type = f"provider_error:{original}"
    serialized_log = SafeJsonFormatter().format(record)
    serialized_metrics = json.dumps(PrivacyMetrics().snapshot())

    assert original not in serialized_log
    assert original not in serialized_metrics


def test_provider_http_error_body_pii_is_redacted(settings) -> None:
    provider_email = "http.error.owner@example.net"

    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            json={
                "error": {
                    "type": "provider_error",
                    "message": f"Rejected {provider_email}",
                }
            },
            request=request,
        )

    upstream = LLMClient(
        "https://provider.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Safe synthetic prompt"}],
        },
    )

    assert response.status_code == 429
    assert provider_email not in response.text
    assert "[REDACTED_PROVIDER_EMAIL]" in response.text
