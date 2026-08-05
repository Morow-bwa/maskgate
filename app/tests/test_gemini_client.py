import asyncio

import httpx

from app.proxy.gemini_client import GeminiClient


def test_gemini_payload_preserves_system_and_conversation_roles() -> None:
    payload = {
        "model": "gemini-2.5-flash",
        "messages": [
            {"role": "system", "content": "Be concise."},
            {"role": "user", "content": "Hello <EMAIL_1>"},
            {"role": "assistant", "content": "Hi."},
        ],
        "temperature": 0.4,
        "max_tokens": 200,
    }
    converted = GeminiClient.to_gemini_payload(payload)
    assert converted["systemInstruction"] == {"parts": [{"text": "Be concise."}]}
    assert converted["contents"][0] == {"role": "user", "parts": [{"text": "Hello <EMAIL_1>"}]}
    assert converted["contents"][1] == {"role": "model", "parts": [{"text": "Hi."}]}
    assert converted["generationConfig"] == {"temperature": 0.4, "maxOutputTokens": 200}


def test_gemini_response_becomes_openai_compatible() -> None:
    response = GeminiClient.from_gemini_response(
        {
            "candidates": [
                {
                    "content": {"parts": [{"text": "Hello <EMAIL_1>"}]},
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 4, "totalTokenCount": 7},
        },
        "gemini-2.5-flash",
    )
    assert response["object"] == "chat.completion"
    assert response["choices"][0]["message"]["content"] == "Hello <EMAIL_1>"
    assert response["usage"]["total_tokens"] == 7


def test_gemini_request_keeps_api_key_out_of_url() -> None:
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("x-goog-api-key")
        return httpx.Response(
            200,
            json={"candidates": [{"content": {"parts": [{"text": "ok"}]}}]},
            request=request,
        )

    client = GeminiClient(
        "https://generativelanguage.googleapis.com/v1beta",
        "local-test-secret",
        transport=httpx.MockTransport(handler),
    )
    result = asyncio.run(client.complete({"model": "gemini-2.5-flash", "messages": [{"role": "user", "content": "Hi"}]}))
    assert result.status_code == 200
    assert seen["key"] == "local-test-secret"
    assert "local-test-secret" not in str(seen["url"])


def test_gemini_stream_is_converted_to_openai_chunks() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text='data: {"candidates":[{"content":{"parts":[{"text":"Hello <EMAIL_1>"}]},"finishReason":"STOP"}]}\n\n',
            request=request,
        )

    client = GeminiClient(
        "https://generativelanguage.googleapis.com/v1beta",
        "local-test-secret",
        transport=httpx.MockTransport(handler),
    )

    async def collect() -> list[dict]:
        return [
            event
            async for event in client.complete_stream(
                {"model": "gemini-2.5-flash", "messages": [{"role": "user", "content": "Hi"}]}
            )
        ]

    events = asyncio.run(collect())
    assert events[0]["object"] == "chat.completion.chunk"
    assert events[0]["choices"][0]["delta"]["content"] == "Hello <EMAIL_1>"
