from __future__ import annotations

import json
import re
import warnings
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from typing import Any, Callable
from zipfile import ZIP_DEFLATED, ZipFile

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.proxy.gemini_client import GeminiClient
from app.proxy.llm_client import LLMClient

CORPUS_PATH = Path(__file__).parents[2] / "evaluation" / "adversarial" / "final_red_team.json"
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
FIXTURES = CORPUS["fixtures"]

PRIMARY_EMAIL = FIXTURES["primary_email"]
SECONDARY_EMAIL = FIXTURES["secondary_email"]
STALE_EMAIL = FIXTURES["stale_email"]
PROVIDER_EMAIL = FIXTURES["provider_email"]
FOREIGN_TOKEN = FIXTURES["foreign_token"]
TOKEN_PATTERN = re.compile(r"<MG:[A-Z2-7]{26}>")

CONTENT_TYPES = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    b'<Default Extension="rels" '
    b'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    b'<Default Extension="xml" ContentType="application/xml"/>'
    b'<Override PartName="/word/document.xml" '
    b'ContentType="application/vnd.openxmlformats-officedocument.'
    b'wordprocessingml.document.main+xml"/>'
    b"</Types>"
)
ROOT_RELS = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<Relationships xmlns="http://schemas.openxmlformats.org/package/'
    b'2006/relationships">'
    b'<Relationship Id="rId1" '
    b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
    b'officeDocument" Target="word/document.xml"/>'
    b"</Relationships>"
)
DOCUMENT = b"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Synthetic document</w:t></w:r></w:p></w:body>
</w:document>"""

ProviderHandler = Callable[[httpx.Request], httpx.Response]


def _token_from_bytes(body: bytes) -> str:
    token = TOKEN_PATTERN.search(body.decode("utf-8"))
    assert token is not None
    return token.group(0)


def _openai_response(request: httpx.Request, content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-synthetic-red-team",
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


def _gemini_response(request: httpx.Request, content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "candidates": [
                {
                    "content": {"parts": [{"text": content}]},
                    "finishReason": "STOP",
                }
            ]
        },
        request=request,
    )


def _client_for_provider(
    settings: Any,
    provider: str,
    handler: ProviderHandler,
    **setting_overrides: Any,
) -> TestClient:
    transport = httpx.MockTransport(handler)
    if provider == "gemini":
        upstream: Any = GeminiClient(
            "https://gemini.invalid/v1beta",
            "",
            transport=transport,
        )
        configured = replace(
            settings,
            llm_provider="gemini",
            gemini_model="gemini-test",
            **setting_overrides,
        )
    else:
        upstream = LLMClient(
            "https://openai.invalid/v1",
            "",
            transport=transport,
        )
        configured = replace(
            settings,
            llm_provider="openai",
            **setting_overrides,
        )
    return TestClient(create_app(configured, llm_client=upstream))


def _rich_openai_request(provider: str) -> dict[str, Any]:
    schema = {
        "type": "object",
        "properties": {
            "recipient": {
                "type": "string",
                "description": f"Synthetic schema contact {PRIMARY_EMAIL}",
            }
        },
        "required": ["recipient"],
    }
    payload: dict[str, Any] = {
        "model": "gemini-test" if provider == "gemini" else "gpt-test",
        "messages": [
            {
                "role": "system",
                "content": f"Synthetic system contact {PRIMARY_EMAIL}",
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": f"Send a notice to {PRIMARY_EMAIL}",
                    }
                ],
            },
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "response" if provider == "gemini" else "synthetic_result",
                "strict": True,
                "schema": schema,
            },
        },
        "stop": [f"stop before {PRIMARY_EMAIL}"],
    }
    if provider == "openai":
        payload["messages"].extend(
            [
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_synthetic_1",
                            "type": "function",
                            "function": {
                                "name": "notify_synthetic",
                                "arguments": json.dumps(
                                    {"recipient": PRIMARY_EMAIL},
                                    separators=(",", ":"),
                                ),
                            },
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": "call_synthetic_1",
                    "content": json.dumps(
                        {"confirmed_recipient": PRIMARY_EMAIL},
                        separators=(",", ":"),
                    ),
                },
            ]
        )
        payload["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": "notify_synthetic",
                    "description": f"Notify synthetic contact {PRIMARY_EMAIL}",
                    "parameters": schema,
                    "strict": True,
                },
            }
        ]
        payload["metadata"] = {"synthetic_contact": PRIMARY_EMAIL}
        payload["user"] = PRIMARY_EMAIL
    return payload


@pytest.mark.parametrize("provider", ["openai", "gemini"])
def test_exact_provider_bytes_exclude_originals_across_supported_fields(
    settings: Any,
    provider: str,
) -> None:
    bodies: list[bytes] = []

    def remote(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        if provider == "gemini":
            return _gemini_response(request, "Synthetic provider acknowledgement")
        return _openai_response(request, "Synthetic provider acknowledgement")

    client = _client_for_provider(settings, provider, remote)
    response = client.post(
        "/v1/chat/completions",
        json=_rich_openai_request(provider),
    )

    assert response.status_code == 200, response.text
    assert len(bodies) == 1
    body = bodies[0]
    parsed = json.loads(body)
    assert body == json.dumps(
        parsed,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert PRIMARY_EMAIL.encode() not in body
    assert TOKEN_PATTERN.search(body.decode("utf-8"))
    if provider == "gemini":
        assert b"systemInstruction" in body
        assert b"generationConfig" in body
    else:
        assert b"tool_calls" in body
        assert b"response_format" in body
        assert b"metadata" in body
        assert b'"store":false' in body


@pytest.mark.parametrize(
    ("provider", "payload"),
    [
        (
            "openai",
            {
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "safe synthetic text"}],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "response",
                        "strict": True,
                        "schema": {
                            "type": "object",
                            "properties": {"answer": {"type": "string"}},
                            "additionalProperties": False,
                        },
                    },
                },
            },
        ),
        (
            "gemini",
            {
                "model": "gemini-test",
                "messages": [{"role": "user", "content": "safe synthetic text"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "lookup",
                            "description": "Synthetic lookup",
                            "parameters": {
                                "type": "object",
                                "properties": {"query": {"type": "string"}},
                            },
                        },
                    }
                ],
            },
        ),
    ],
    ids=["openai-additionalProperties", "gemini-functionDeclarations"],
)
def test_documented_protocol_keys_are_not_misclassified_as_base64(
    settings: Any,
    provider: str,
    payload: dict[str, Any],
) -> None:
    bodies: list[bytes] = []

    def remote(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        if provider == "gemini":
            return _gemini_response(request, "Synthetic success")
        return _openai_response(request, "Synthetic success")

    client = _client_for_provider(settings, provider, remote)
    response = client.post("/v1/chat/completions", json=payload)

    assert response.status_code == 200, response.text
    assert len(bodies) == 1


@pytest.mark.parametrize("provider", ["openai", "gemini"])
@pytest.mark.parametrize(
    "case",
    CORPUS["wire_encodings"],
    ids=[case["id"] for case in CORPUS["wire_encodings"]],
)
def test_common_encodings_are_blocked_before_provider_transport(
    settings: Any,
    provider: str,
    case: dict[str, str],
) -> None:
    calls: list[bytes] = []

    def remote(request: httpx.Request) -> httpx.Response:
        calls.append(request.content)
        if provider == "gemini":
            return _gemini_response(request, "unexpected")
        return _openai_response(request, "unexpected")

    client = _client_for_provider(settings, provider, remote)
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gemini-test" if provider == "gemini" else "gpt-test",
            "messages": [{"role": "user", "content": case["value"]}],
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["type"] in {
        "policy_block",
        "wire_privacy_violation",
    }
    assert calls == []


def test_output_rehydrates_only_the_current_active_token(settings: Any) -> None:
    bodies: list[bytes] = []
    tokens: list[str] = []

    def remote(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        active_token = _token_from_bytes(request.content)
        tokens.append(active_token)
        if len(tokens) == 1:
            return _openai_response(request, "First synthetic turn accepted")
        return _openai_response(
            request,
            (
                f"active {active_token}; stale {tokens[0]}; "
                f"foreign {FOREIGN_TOKEN}; novel {PROVIDER_EMAIL}"
            ),
        )

    client = _client_for_provider(settings, "openai", remote)
    first = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": f"First {PRIMARY_EMAIL}"}],
        },
    )
    second = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": f"Second {SECONDARY_EMAIL}"}],
        },
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(set(tokens)) == 2
    content = second.json()["choices"][0]["message"]["content"]
    assert SECONDARY_EMAIL in content
    assert PRIMARY_EMAIL not in content
    assert PROVIDER_EMAIL not in content
    assert tokens[0] not in content
    assert FOREIGN_TOKEN not in content
    assert content.count("[REDACTED_PROVIDER_TOKEN]") == 2
    assert "[REDACTED_PROVIDER_EMAIL]" in content
    assert all(PRIMARY_EMAIL.encode() not in body for body in bodies)
    assert all(SECONDARY_EMAIL.encode() not in body for body in bodies)
    assert client.app.state.mapping_store.size() == 0


def test_separate_bearers_cannot_share_one_conversation_vault(settings: Any) -> None:
    bodies: list[bytes] = []
    tenant_a_token = ""

    def remote(request: httpx.Request) -> httpx.Response:
        nonlocal tenant_a_token
        bodies.append(request.content)
        if len(bodies) == 1:
            tenant_a_token = _token_from_bytes(request.content)
            return _openai_response(request, "Tenant A stored")
        return _openai_response(request, tenant_a_token)

    client = _client_for_provider(
        settings,
        "openai",
        remote,
        api_keys=(FIXTURES["tenant_a_bearer"], FIXTURES["tenant_b_bearer"]),
    )
    conversation_id = "shared_synthetic_conversation"
    first = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {FIXTURES['tenant_a_bearer']}"},
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": f"Store {PRIMARY_EMAIL}"}],
        },
    )
    second = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {FIXTURES['tenant_b_bearer']}"},
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "continue separately"}],
        },
    )

    assert first.status_code == 200
    assert second.status_code == 200
    second_content = second.json()["choices"][0]["message"]["content"]
    assert PRIMARY_EMAIL not in second_content
    assert tenant_a_token not in second_content
    assert second_content == "[REDACTED_PROVIDER_TOKEN]"
    assert PRIMARY_EMAIL.encode() not in bodies[1]
    assert tenant_a_token.encode() not in bodies[1]
    assert client.app.state.conversation_store.size() == 2


def _stream_event(choices: list[dict[str, Any]]) -> str:
    return f"data: {json.dumps({'choices': choices}, separators=(',', ':'))}\n\n"


def test_openai_stream_buffers_content_refusal_and_tool_argument_fragments(
    settings: Any,
) -> None:
    bodies: list[bytes] = []
    unsafe_prefix, unsafe_suffix = PROVIDER_EMAIL.split("@", 1)
    unsafe_prefix += "@"

    def remote(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        token = _token_from_bytes(request.content)
        first_choices = [
            {"index": 0, "delta": {"content": token[:11]}},
            {
                "index": 1,
                "delta": {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_stream_synthetic",
                            "function": {"arguments": f'{{"email":"{unsafe_prefix}'},
                        }
                    ]
                },
            },
            {
                "index": 2,
                "delta": {
                    "function_call": {
                        "name": "legacy_synthetic",
                        "arguments": f'{{"email":"{unsafe_prefix}',
                    }
                },
            },
            {"index": 3, "delta": {"refusal": unsafe_prefix}},
        ]
        second_choices = [
            {"index": 0, "delta": {"content": token[11:]}},
            {
                "index": 1,
                "delta": {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_stream_synthetic",
                            "function": {"arguments": f'{unsafe_suffix}"}}'},
                        }
                    ]
                },
            },
            {
                "index": 2,
                "delta": {
                    "function_call": {
                        "name": "legacy_synthetic",
                        "arguments": f'{unsafe_suffix}"}}',
                    }
                },
            },
            {"index": 3, "delta": {"refusal": unsafe_suffix}},
        ]
        stream = _stream_event(first_choices) + _stream_event(second_choices) + "data: [DONE]\n\n"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text=stream,
            request=request,
        )

    client = _client_for_provider(settings, "openai", remote)
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "stream": True,
            "messages": [{"role": "user", "content": f"Stream {PRIMARY_EMAIL}"}],
        },
    )

    assert response.status_code == 200
    assert PRIMARY_EMAIL.encode() not in bodies[0]
    assert PRIMARY_EMAIL in response.text
    assert PROVIDER_EMAIL not in response.text
    assert unsafe_prefix not in response.text
    assert unsafe_suffix not in response.text
    assert not TOKEN_PATTERN.search(response.text)
    assert response.text.count("[REDACTED_PROVIDER_EMAIL]") == 3
    assert response.text.rstrip().endswith("data: [DONE]")


def test_gemini_stream_buffers_fragmented_provider_text(settings: Any) -> None:
    bodies: list[bytes] = []

    def remote(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        token = _token_from_bytes(request.content)
        fragments = [
            f"known {token[:9]}",
            f"{token[9:]}; novel {PROVIDER_EMAIL[:13]}",
            PROVIDER_EMAIL[13:],
        ]
        stream = "".join(
            "data: "
            + json.dumps(
                {"candidates": [{"content": {"parts": [{"text": fragment}]}}]},
                separators=(",", ":"),
            )
            + "\n\n"
            for fragment in fragments
        )
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text=stream,
            request=request,
        )

    client = _client_for_provider(settings, "gemini", remote)
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gemini-test",
            "stream": True,
            "messages": [{"role": "user", "content": f"Stream {PRIMARY_EMAIL}"}],
        },
    )

    assert response.status_code == 200
    assert PRIMARY_EMAIL.encode() not in bodies[0]
    assert PRIMARY_EMAIL in response.text
    assert PROVIDER_EMAIL not in response.text
    assert PROVIDER_EMAIL[:13] not in response.text
    assert PROVIDER_EMAIL[13:] not in response.text
    assert not TOKEN_PATTERN.search(response.text)
    assert "[REDACTED_PROVIDER_EMAIL]" in response.text


def test_openai_stream_preserves_safe_protocol_metadata(settings: Any) -> None:
    def remote(request: httpx.Request) -> httpx.Response:
        stream = _stream_event(
            [
                {
                    "index": 0,
                    "delta": {"content": "safe synthetic fragment"},
                    "finish_reason": "stop",
                }
            ]
        )
        event = json.loads(stream.removeprefix("data: ").strip())
        event.update(
            {
                "id": "chatcmpl-synthetic-stream",
                "object": "chat.completion.chunk",
            }
        )
        body = f"data: {json.dumps(event, separators=(',', ':'))}\n\ndata: [DONE]\n\n"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text=body,
            request=request,
        )

    client = _client_for_provider(settings, "openai", remote)
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "stream": True,
            "messages": [{"role": "user", "content": "safe synthetic request"}],
        },
    )

    assert response.status_code == 200
    assert "chat.completion.chunk" in response.text
    assert "[REDACTED_PROVIDER_DOMAIN]" not in response.text


def test_deleted_conversation_mapping_cannot_be_rehydrated(
    settings: Any,
    playground_dir: Path,
) -> None:
    old_token = ""

    def remote(request: httpx.Request) -> httpx.Response:
        nonlocal old_token
        if not old_token:
            old_token = _token_from_bytes(request.content)
            return _openai_response(request, old_token)
        return _openai_response(request, old_token)

    transport = httpx.MockTransport(remote)
    upstream = LLMClient("https://openai.invalid/v1", "", transport=transport)
    configured = replace(settings, llm_provider="openai")
    client = TestClient(create_app(configured, llm_client=upstream, playground_dir=playground_dir))
    conversation_id = "delete_synthetic_conversation"
    first = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": f"Remember {PRIMARY_EMAIL}"}],
        },
    )
    deleted = client.delete(f"/playground/api/conversations/{conversation_id}")
    second = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "start clean"}],
        },
    )

    assert first.status_code == 200
    assert PRIMARY_EMAIL in first.json()["choices"][0]["message"]["content"]
    assert deleted.status_code == 200
    assert second.status_code == 200
    assert second.json()["choices"][0]["message"]["content"] == ("[REDACTED_PROVIDER_TOKEN]")
    assert client.app.state.conversation_store.size() == 1


def test_trimmed_conversation_prunes_unreferenced_mapping(settings: Any) -> None:
    bodies: list[bytes] = []
    old_token = ""

    def remote(request: httpx.Request) -> httpx.Response:
        nonlocal old_token
        bodies.append(request.content)
        if len(bodies) == 1:
            old_token = _token_from_bytes(request.content)
            return _openai_response(request, old_token)
        if len(bodies) == 4:
            return _openai_response(request, old_token)
        return _openai_response(request, f"safe synthetic reply {len(bodies)}")

    client = _client_for_provider(
        settings,
        "openai",
        remote,
        conversation_max_messages=4,
    )
    conversation_id = "trim_synthetic_conversation"
    requests = [
        f"remember {PRIMARY_EMAIL}",
        "continue step two",
        "continue step three",
        "continue after trim",
    ]
    responses = [
        client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-test",
                "conversation_id": conversation_id,
                "messages": [{"role": "user", "content": content}],
            },
        )
        for content in requests
    ]

    assert all(response.status_code == 200 for response in responses)
    assert old_token.encode() not in bodies[3]
    assert PRIMARY_EMAIL.encode() not in bodies[3]
    assert responses[3].json()["choices"][0]["message"]["content"] == ("[REDACTED_PROVIDER_TOKEN]")
    assert client.app.state.mapping_store.size() == 0


def test_expired_conversation_mapping_cannot_be_rehydrated(settings: Any) -> None:
    old_token = ""
    clock = [100.0]

    def remote(request: httpx.Request) -> httpx.Response:
        nonlocal old_token
        if not old_token:
            old_token = _token_from_bytes(request.content)
            return _openai_response(request, old_token)
        return _openai_response(request, old_token)

    client = _client_for_provider(
        settings,
        "openai",
        remote,
        conversation_ttl_seconds=1,
    )
    store = client.app.state.conversation_store
    store._clock = lambda: clock[0]
    conversation_id = "expiry_synthetic_conversation"
    first = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": f"Remember {STALE_EMAIL}"}],
        },
    )
    clock[0] = 102.0
    removed = store.cleanup()
    second = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "start after expiry"}],
        },
    )

    assert first.status_code == 200
    assert removed == 1
    assert second.status_code == 200
    assert second.json()["choices"][0]["message"]["content"] == ("[REDACTED_PROVIDER_TOKEN]")


def test_request_logs_and_metrics_exclude_fixture_values(
    settings: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def remote(request: httpx.Request) -> httpx.Response:
        return _openai_response(request, "Synthetic metrics acknowledgement")

    client = _client_for_provider(
        settings,
        "openai",
        remote,
        log_level="INFO",
    )
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-test",
            "messages": [{"role": "user", "content": f"Observe {PRIMARY_EMAIL}"}],
        },
    )
    captured = capsys.readouterr().out
    metrics = json.dumps(
        client.app.state.privacy_metrics.snapshot(),
        ensure_ascii=False,
        sort_keys=True,
    )

    assert response.status_code == 200
    assert "request_completed" in captured
    for fixture in (PRIMARY_EMAIL, SECONDARY_EMAIL, STALE_EMAIL, PROVIDER_EMAIL):
        assert fixture not in captured
        assert fixture not in metrics
    assert "detections_total:EMAIL" in metrics


def _hostile_docx(case_id: str) -> bytes:
    output = BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with ZipFile(output, "w", ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("_rels/.rels", ROOT_RELS)
            archive.writestr("word/document.xml", DOCUMENT)
            if case_id == "zip-traversal":
                archive.writestr("../escape.xml", b"synthetic traversal fixture")
            elif case_id == "duplicate-document-part":
                archive.writestr("word/document.xml", DOCUMENT)
            elif case_id == "macro-project":
                archive.writestr("word/vbaProject.bin", b"synthetic macro fixture")
            elif case_id == "embedded-object":
                archive.writestr("word/embeddings/object1.bin", b"synthetic object fixture")
            elif case_id == "unknown-opaque-part":
                archive.writestr("attachments/private.bin", PRIMARY_EMAIL.encode())
            else:  # pragma: no cover - corpus and test are versioned together
                raise AssertionError(f"unknown hostile DOCX case: {case_id}")
    return output.getvalue()


@pytest.mark.parametrize(
    "case",
    CORPUS["hostile_docx"],
    ids=[case["id"] for case in CORPUS["hostile_docx"]],
)
def test_hostile_docx_packages_remain_blocked(
    settings: Any,
    case: dict[str, Any],
) -> None:
    client = TestClient(create_app(settings, llm_client=object()))
    response = client.post(
        "/v1/privacy/files/anonymize",
        files={
            "file": (
                "synthetic-hostile.docx",
                _hostile_docx(case["id"]),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )

    assert response.status_code == case["expected_status"]
    assert response.json()["error"]["type"] == case["expected_error"]
    assert PRIMARY_EMAIL not in response.text
