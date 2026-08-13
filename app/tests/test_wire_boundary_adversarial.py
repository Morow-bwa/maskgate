from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from app.privacy.wire import WirePrivacyViolation
from app.proxy.llm_client import LLMClient

CORPUS_PATH = Path(__file__).parents[2] / "evaluation" / "adversarial" / "media_cases.json"
WIRE_CASES = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))["wire_cases"]


@pytest.mark.parametrize("stream", [False, True], ids=["nonstream", "stream"])
@pytest.mark.parametrize("case", WIRE_CASES, ids=lambda case: case["id"])
def test_adversarial_value_never_reaches_openai_compatible_transport(
    case: dict[str, object],
    stream: bool,
) -> None:
    transport_calls: list[bytes] = []

    def provider(request: httpx.Request) -> httpx.Response:
        transport_calls.append(request.content)
        raise AssertionError("the final wire guard must reject before network transport")

    upstream = LLMClient(
        "https://provider.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    payload = {
        "model": "synthetic-test-model",
        "messages": [{"role": "user", "content": "Process this synthetic fixture"}],
        "metadata": {"adversarial_probe": case["value"]},
        "stream": stream,
    }

    async def invoke_transport_path() -> None:
        if stream:
            async for _ in upstream.complete_stream(payload):
                pass
        else:
            await upstream.complete(payload)

    with pytest.raises(WirePrivacyViolation):
        asyncio.run(invoke_transport_path())

    assert case["expected_error"] == "wire_privacy_violation"
    assert transport_calls == []


def test_corpus_contains_every_required_wire_evasion_class() -> None:
    classes = {str(case["class"]) for case in WIRE_CASES}

    assert classes == {
        "base64",
        "hex",
        "nested_json",
        "numeric_pii",
        "percent_escape",
        "unicode_escape",
        "user_injected_token",
    }
