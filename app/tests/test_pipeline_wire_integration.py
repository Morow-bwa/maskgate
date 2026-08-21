from __future__ import annotations

import json
import re
from dataclasses import replace

import httpx
from fastapi.testclient import TestClient

from app.main import create_app
from app.proxy.gemini_client import GeminiClient
from app.proxy.llm_client import LLMClient

TOKEN = re.compile(r"<MG:[A-Z2-7]{26}>")


def test_openai_adapter_guard_and_transport_share_exact_bytes(settings) -> None:
    seen: dict[str, object] = {}

    def provider(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content
        seen["url"] = str(request.url)
        payload = json.loads(request.content)
        user_text = payload["messages"][-1]["content"]
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-wire-test",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": user_text},
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
            "messages": [{"role": "user", "content": "Email owner@example.com"}],
        },
    )

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == ("Email owner@example.com")
    body = seen["body"]
    assert isinstance(body, bytes)
    payload = json.loads(body)
    token = TOKEN.search(payload["messages"][-1]["content"])
    assert token is not None
    expected = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert body == expected
    assert b"owner@example.com" not in body
    assert payload["store"] is False
    assert str(seen["url"]).endswith("/v1/chat/completions")


def test_gemini_adapter_guard_and_transport_share_exact_bytes(settings) -> None:
    seen: dict[str, object] = {}

    def provider(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content
        seen["url"] = str(request.url)
        payload = json.loads(request.content)
        user_text = payload["contents"][-1]["parts"][0]["text"]
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {"parts": [{"text": user_text}]},
                        "finishReason": "STOP",
                    }
                ]
            },
            request=request,
        )

    upstream = GeminiClient(
        "https://generativelanguage.googleapis.com/v1beta",
        "synthetic-gemini-key",
        transport=httpx.MockTransport(provider),
    )
    configured = replace(
        settings,
        llm_provider="gemini",
        gemini_model="gemini-2.5-flash",
    )
    client = TestClient(create_app(configured, llm_client=upstream))

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gemini-2.5-flash",
            "messages": [{"role": "user", "content": "Email owner@example.com"}],
        },
    )

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == ("Email owner@example.com")
    body = seen["body"]
    assert isinstance(body, bytes)
    payload = json.loads(body)
    assert set(payload) == {"contents", "systemInstruction"}
    assert TOKEN.search(payload["contents"][-1]["parts"][0]["text"])
    assert body == json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert b"owner@example.com" not in body
    assert str(seen["url"]).endswith("/v1beta/models/gemini-2.5-flash:generateContent")


def test_malformed_success_response_fails_closed(settings) -> None:
    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []}, request=request)

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
            "messages": [{"role": "user", "content": "Hello"}],
        },
    )

    assert response.status_code == 502
    assert response.json()["error"]["type"] == "upstream_invalid_response"


def test_malformed_stream_event_becomes_safe_error_event(settings) -> None:
    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text='data: {"choices":[{"index":0,"delta":{"content":42}}]}\n\n',
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
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert "upstream_invalid_stream" in response.text
    assert '"content": 42' not in response.text
