from __future__ import annotations

import asyncio

import httpx
import pytest

from app.proxy.llm_client import LLMClient, LLMUpstreamError, bounded_sse_lines


def test_stream_limit_is_enforced_before_a_newline_arrives() -> None:
    consumed = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for index in range(20):
                consumed.append(index)
                yield b"x" * 512

    async def collect():
        response = httpx.Response(200, stream=Stream())
        return [line async for line in bounded_sse_lines(response, 1024)]

    with pytest.raises(LLMUpstreamError) as exc_info:
        asyncio.run(collect())
    assert exc_info.value.error_type == "upstream_response_too_large"
    assert len(consumed) == 3


@pytest.mark.parametrize("ending", ["\n", "\r", "\r\n"])
def test_stream_lines_preserve_utf8_and_split_line_endings(ending) -> None:
    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for value in ("data: Привет" + ending + ending + "tail").encode():
                yield bytes([value])

    async def collect():
        response = httpx.Response(200, stream=Stream())
        return [line async for line in bounded_sse_lines(response, 1024)]

    assert asyncio.run(collect()) == ["data: Привет", "", "tail"]


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


def test_client_reuses_pool_without_forwarding_response_cookies_or_following_redirects() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={"choices": []},
                headers={"set-cookie": "provider_state=forbidden; Path=/"},
                request=request,
            )
        return httpx.Response(
            307,
            json={"redirect": "not-followed"},
            headers={"location": "https://other.invalid/collect"},
            request=request,
        )

    client = LLMClient(
        "https://provider.invalid/v1",
        "test-provider-key",
        transport=httpx.MockTransport(handler),
    )

    async def exercise() -> tuple[int, int, bool]:
        first = await client.complete({"model": "test", "messages": []})
        pool_id = id(client._client)
        second = await client.complete({"model": "test", "messages": []})
        reused = pool_id == id(client._client)
        await client.aclose()
        return first.status_code, second.status_code, reused

    assert asyncio.run(exercise()) == (200, 307, True)
    assert len(requests) == 2
    assert all("cookie" not in request.headers for request in requests)
    assert requests[1].url.host == "provider.invalid"
    assert client._closed is True
