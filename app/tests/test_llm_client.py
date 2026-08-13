from __future__ import annotations

import asyncio

import httpx
import pytest

from app.proxy.llm_client import LLMClient, LLMUpstreamError


def test_complete_rejects_oversized_provider_response() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": "x" * 2_000}, request=request)

    client = LLMClient(
        "https://provider.invalid/v1",
        "test-provider-key",
        max_response_bytes=1_024,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(LLMUpstreamError) as exc_info:
        asyncio.run(client.complete({"model": "test", "messages": []}))

    assert exc_info.value.error_type == "upstream_response_too_large"


def test_stream_rejects_oversized_provider_response() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        line = 'data: {"choices":[{"delta":{"content":"' + ("x" * 2_000) + '"}}]}\n\n'
        return httpx.Response(
            200,
            text=line,
            headers={"content-type": "text/event-stream"},
            request=request,
        )

    client = LLMClient(
        "https://provider.invalid/v1",
        "test-provider-key",
        max_response_bytes=1_024,
        transport=httpx.MockTransport(handler),
    )

    async def collect() -> list[dict]:
        return [event async for event in client.complete_stream({"stream": True})]

    with pytest.raises(LLMUpstreamError) as exc_info:
        asyncio.run(collect())

    assert exc_info.value.error_type == "upstream_response_too_large"


def test_stream_rejects_malformed_sse_instead_of_returning_success() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="data: {not-json}\n\n",
            headers={"content-type": "text/event-stream"},
            request=request,
        )

    client = LLMClient(
        "https://provider.invalid/v1",
        "test-provider-key",
        transport=httpx.MockTransport(handler),
    )

    async def collect() -> list[dict]:
        return [event async for event in client.complete_stream({"stream": True})]

    with pytest.raises(LLMUpstreamError) as exc_info:
        asyncio.run(collect())

    assert exc_info.value.error_type == "upstream_invalid_stream"


def test_stream_parser_supports_multiline_sse_data() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text='data: {"choices":\ndata: []}\n\ndata: [DONE]\n\n',
            headers={"content-type": "text/event-stream"},
            request=request,
        )

    client = LLMClient(
        "https://provider.invalid/v1",
        "test-provider-key",
        transport=httpx.MockTransport(handler),
    )

    async def collect() -> list[dict]:
        return [event async for event in client.complete_stream({"stream": True})]

    assert asyncio.run(collect()) == [{"choices": []}]
