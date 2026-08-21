from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.main import create_app
from app.providers import OpenAIResponsesAdapter
from app.proxy.llm_client import LLMClient

TOKEN = re.compile(r"<MG:[A-Z2-7]{26}>")


def test_responses_adapter_preserves_plain_function_output_text() -> None:
    adapter = OpenAIResponsesAdapter()
    canonical = adapter.from_wire(
        {
            "model": "gpt-test",
            "input": [
                {
                    "type": "function_call_output",
                    "call_id": "call_1",
                    "output": "plain result",
                }
            ],
        }
    )

    assert adapter.to_wire(canonical)["input"][0]["output"] == "plain result"


def test_responses_route_masks_canonical_items_and_sends_exact_checked_bytes(settings) -> None:
    seen: dict[str, object] = {}

    def provider(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content
        seen["url"] = str(request.url)
        payload = json.loads(request.content)
        masked = payload["input"][0]["content"][0]["text"]
        return httpx.Response(
            200,
            json={
                "id": "resp_test",
                "object": "response",
                "status": "completed",
                "output": [
                    {
                        "id": "msg_test",
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": masked, "annotations": []}],
                    }
                ],
            },
            request=request,
        )

    upstream = LLMClient(
        "https://api.openai.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))

    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-test",
            "input": "Email owner@example.com",
            "tools": [
                {
                    "type": "function",
                    "name": "lookup_customer",
                    "description": "Lookup owner@example.com",
                    "parameters": {
                        "type": "object",
                        "properties": {"customer_email": {"type": "string"}},
                        "required": ["customer_email"],
                        "additionalProperties": False,
                    },
                    "strict": True,
                }
            ],
        },
    )

    assert response.status_code == 200
    assert response.json()["output"][0]["content"][0]["text"] == ("Email owner@example.com")
    body = seen["body"]
    assert isinstance(body, bytes)
    payload = json.loads(body)
    assert body == json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert b"owner@example.com" not in body
    assert TOKEN.search(payload["input"][0]["content"][0]["text"])
    assert TOKEN.search(payload["tools"][0]["description"])
    assert payload["store"] is False
    assert payload["stream"] is False
    assert str(seen["url"]).endswith("/v1/responses")


def test_responses_route_inspects_tool_arguments_results_and_schema_keys(settings) -> None:
    seen: dict[str, object] = {}

    def provider(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        seen["payload"] = payload
        arguments = payload["input"][1]["arguments"]
        return httpx.Response(
            200,
            json={
                "id": "resp_tools",
                "object": "response",
                "status": "completed",
                "output": [
                    {
                        "id": "fc_test",
                        "type": "function_call",
                        "status": "completed",
                        "call_id": "call_1",
                        "name": "lookup_customer",
                        "arguments": arguments,
                    }
                ],
            },
            request=request,
        )

    upstream = LLMClient(
        "https://api.openai.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-test",
            "input": [
                {"type": "message", "role": "user", "content": "Look up the customer"},
                {
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "lookup_customer",
                    "arguments": '{"customer_email":"owner@example.com"}',
                },
                {
                    "type": "function_call_output",
                    "call_id": "call_1",
                    "output": '{"owner@example.com":"active"}',
                },
            ],
            "tools": [
                {
                    "type": "function",
                    "name": "lookup_customer",
                    "description": "Find owner@example.com",
                    "parameters": {
                        "type": "object",
                        "properties": {"owner@example.com": {"type": "string"}},
                        "additionalProperties": False,
                    },
                    "strict": True,
                }
            ],
        },
    )

    assert response.status_code == 200
    payload = seen["payload"]
    assert isinstance(payload, dict)
    assert "owner@example.com" not in json.dumps(payload)
    assert payload["input"][1]["call_id"] == "call_1"
    assert payload["input"][1]["name"] == "lookup_customer"
    assert TOKEN.search(payload["input"][1]["arguments"])
    assert TOKEN.search(payload["input"][2]["output"])
    assert any(TOKEN.search(key) for key in payload["tools"][0]["parameters"]["properties"])
    assert json.loads(response.json()["output"][0]["arguments"]) == {
        "customer_email": "owner@example.com"
    }


def test_responses_route_never_returns_unvalidated_provider_error_bodies(settings) -> None:
    raw_pii = "error-owner@example.com"

    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "id": raw_pii,
                "error": {"message": raw_pii, "nested": {"raw": raw_pii}},
            },
            request=request,
        )

    upstream = LLMClient(
        "https://api.openai.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))
    response = client.post(
        "/v1/responses",
        json={"model": "gpt-test", "input": "safe input"},
    )

    assert response.status_code == 502
    assert response.json()["error"]["type"] == "upstream_provider_error"
    assert raw_pii not in response.text


def test_responses_route_rejects_pii_disguised_as_provider_identifier(settings) -> None:
    raw_pii = "response-owner@example.com"

    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": raw_pii,
                "object": "response",
                "status": "completed",
                "output": [],
            },
            request=request,
        )

    upstream = LLMClient(
        "https://api.openai.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))
    response = client.post(
        "/v1/responses",
        json={"model": "gpt-test", "input": "safe input"},
    )

    assert response.status_code == 502
    assert response.json()["error"]["type"] == "upstream_invalid_response"
    assert raw_pii not in response.text


def test_responses_route_rejects_unknown_root_output_fields_without_leaking(settings) -> None:
    raw_pii = "unknown-owner@example.com"

    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "resp_valid",
                "object": "response",
                "status": "completed",
                "output": [],
                "unknown": {"raw": raw_pii},
            },
            request=request,
        )

    upstream = LLMClient(
        "https://api.openai.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))
    response = client.post(
        "/v1/responses",
        json={"model": "gpt-test", "input": "safe input"},
    )

    assert response.status_code == 502
    assert response.json()["error"]["type"] == "upstream_invalid_response"
    assert raw_pii not in response.text


def test_responses_route_accepts_realistic_official_response_and_projects_safe_subset(
    settings,
) -> None:
    discarded_pii = "metadata-owner@example.com"

    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "resp_realistic",
                "object": "response",
                "created_at": 1_728_931_840,
                "status": "completed",
                "completed_at": 1_728_931_841,
                "error": None,
                "incomplete_details": None,
                "instructions": discarded_pii,
                "max_output_tokens": 128,
                "model": "gpt-test-2026-01-01",
                "output": [
                    {
                        "id": "msg_realistic",
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": "Safe answer",
                                "annotations": [],
                                "logprobs": [],
                            }
                        ],
                    }
                ],
                "parallel_tool_calls": True,
                "previous_response_id": None,
                "reasoning": {"effort": None, "summary": None},
                "store": False,
                "temperature": 1.0,
                "text": {"format": {"type": "text"}},
                "tool_choice": "auto",
                "tools": [],
                "top_p": 1.0,
                "truncation": "disabled",
                "usage": {
                    "input_tokens": 5,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 2,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": 7,
                },
                "user": None,
                "metadata": {"trace": discarded_pii},
                "background": False,
                "service_tier": "default",
            },
            request=request,
        )

    upstream = LLMClient(
        "https://api.openai.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-test",
            "input": "safe input",
            "max_output_tokens": 128,
            "temperature": 1.0,
            "top_p": 1.0,
        },
    )

    assert response.status_code == 200
    assert set(response.json()) == {"id", "object", "status", "output"}
    assert response.json()["output"][0]["content"][0]["text"] == "Safe answer"
    assert discarded_pii not in response.text


def test_responses_route_redacts_new_provider_generated_pii(settings) -> None:
    generated_pii = "new-owner@example.com"

    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "resp_generated",
                "object": "response",
                "status": "completed",
                "output": [
                    {
                        "id": "msg_generated",
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": generated_pii, "annotations": []}
                        ],
                    }
                ],
            },
            request=request,
        )

    upstream = LLMClient(
        "https://api.openai.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))
    response = client.post(
        "/v1/responses",
        json={"model": "gpt-test", "input": "safe input"},
    )

    assert response.status_code == 200
    assert generated_pii not in response.text
    assert response.json()["output"][0]["content"][0]["text"] == ("[REDACTED_PROVIDER_EMAIL]")


def test_responses_route_rejects_streaming_before_transport(settings) -> None:
    requests: list[httpx.Request] = []

    def provider(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500, request=request)

    upstream = LLMClient(
        "https://api.openai.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))
    response = client.post(
        "/v1/responses",
        json={"model": "gpt-test", "input": "safe input", "stream": True},
    )

    assert response.status_code == 422
    assert response.json()["error"]["type"] == "unsupported_feature"
    assert requests == []


def test_responses_route_blocks_remote_tools_and_provider_state_before_transport(settings) -> None:
    requests: list[httpx.Request] = []

    def provider(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(500, request=request)

    upstream = LLMClient(
        "https://api.openai.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))

    remote_tool = client.post(
        "/v1/responses",
        json={
            "model": "gpt-test",
            "input": "safe input",
            "tools": [{"type": "web_search"}],
        },
    )
    stateful = client.post(
        "/v1/responses",
        json={
            "model": "gpt-test",
            "input": "safe input",
            "previous_response_id": "resp_previous",
        },
    )

    assert remote_tool.status_code == 422
    assert stateful.status_code == 422
    assert requests == []


def test_only_approved_transport_modules_may_import_network_clients() -> None:
    app_root = Path(__file__).parents[1]
    approved = {
        app_root / "proxy" / "gemini_client.py",
        app_root / "proxy" / "llm_client.py",
    }
    offenders: list[str] = []
    network_imports = (
        "import httpx",
        "from httpx",
        "import requests",
        "from requests",
        "import aiohttp",
        "from aiohttp",
        "import socket",
        "from socket",
        "from urllib.request",
    )
    for path in app_root.rglob("*.py"):
        if "tests" in path.parts or path in approved:
            continue
        source = path.read_text(encoding="utf-8")
        if any(marker in source for marker in network_imports):
            offenders.append(str(path.relative_to(app_root)))

    assert offenders == []
