from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import replace
from urllib.parse import quote

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.privacy.detection import DetectorEnsemble
from app.privacy.models import DetectorProfile
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.wire import FinalWirePrivacyGuard, WirePrivacyViolation
from app.proxy.llm_client import LLMClient


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _layered(text: str) -> str:
    for _ in range(6):
        text = quote(text, safe="")
    return text


CASES = [
    _b64("owner@example.com"),
    _b64("x " * 25000 + "owner@example.com"),
    "owner%40example.com",
    _layered("owner@example.com"),
    "%25%36%46" + quote(_b64("owner@example.com"), safe=""),
]


@pytest.mark.parametrize(
    "encoded", CASES, ids=["base64", "oversized", "percent", "layers", "mixed"]
)
@pytest.mark.parametrize("as_key", [False, True], ids=["value", "key"])
def test_encoded_data_is_rejected_at_wire_and_removed_from_output(encoded, as_key) -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
    payload = {encoded: "safe"} if as_key else {"content": encoded}
    with pytest.raises(WirePrivacyViolation):
        FinalWirePrivacyGuard(detector).check(provider="mock", payload=payload)
    output = OutputPrivacyGuard(detector)
    assert encoded not in json.dumps(output.process(payload, []))
    assert encoded not in json.dumps(output.sanitize_for_history(payload, []))


@pytest.mark.parametrize("as_key", [False, True])
def test_encoded_data_never_reaches_transport(as_key) -> None:
    calls = []

    def provider(request):
        calls.append(request.content)
        return httpx.Response(200, json={})

    upstream = LLMClient(
        "https://provider.invalid/v1", "synthetic", transport=httpx.MockTransport(provider)
    )
    encoded = _b64("owner@example.com")
    payload = {"metadata": {encoded: "safe"} if as_key else {"value": encoded}}
    with pytest.raises(WirePrivacyViolation):
        asyncio.run(upstream.complete(payload))
    assert calls == []


def test_protocol_keys_and_long_call_ids_remain_usable() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
    call_id = "call_AbCdEfGhIjKlMnOpQrStUvWx"
    payload = {
        "input": [{"type": "function_call_output", "call_id": call_id, "output": "safe"}],
        "tools": [{"parameters": {"additionalProperties": False}}],
    }
    checked = FinalWirePrivacyGuard(detector).check(provider="openai-responses", payload=payload)
    assert checked.payload == payload
    response = {
        "id": "resp_AbCdEfGhIjKlMnOpQrStUvWx",
        "output": [{"id": "fc_AbCdEfGhIjKlMnOpQrStUvWx", "call_id": call_id}],
    }
    assert OutputPrivacyGuard(detector).process(response, []) == response


def test_call_id_shaped_content_is_not_a_protocol_exception() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
    text = "call_AbCdEfGhIjKlMnOpQrStUvWx"
    for payload in ({"content": text}, {"metadata": {"call_id": text}}, {text: "safe"}):
        with pytest.raises(WirePrivacyViolation):
            FinalWirePrivacyGuard(detector).check(provider="openai-responses", payload=payload)
        assert text not in json.dumps(OutputPrivacyGuard(detector).process(payload, []))


def test_numeric_array_cannot_borrow_scalar_protocol_exception() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
    guard = FinalWirePrivacyGuard(detector)
    assert guard.check(provider="openai-responses", payload={"temperature": 1.0})
    with pytest.raises(WirePrivacyViolation):
        guard.check(provider="openai-responses", payload={"temperature": [4111111111111111]})


@pytest.mark.parametrize(
    "text",
    ["safe " * 14000, "я " * 23000, "%252525252525252540"],
    ids=["ascii-size", "utf8-size", "decode-depth"],
)
def test_inspection_budget_exhaustion_is_never_success(text) -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
    with pytest.raises(WirePrivacyViolation):
        FinalWirePrivacyGuard(detector).check(provider="mock", payload={"content": text})
    result = OutputPrivacyGuard(detector).process_authorized_text(text, [])
    assert text not in result
    assert "REDACTED_PROVIDER" in result


def test_responses_long_ids_survive_a_complete_tool_round_trip(settings) -> None:
    call_id = "call_AbCdEfGhIjKlMnOpQrStUvWxYz"
    response_id = "resp_AbCdEfGhIjKlMnOpQrStUvWxYz"
    function_id = "fc_AbCdEfGhIjKlMnOpQrStUvWxYz"
    bodies = []

    def provider(request):
        bodies.append(request.content)
        payload = json.loads(request.content)
        if len(bodies) == 2:
            assert payload["input"][0]["call_id"] == call_id
            assert payload["input"][1]["call_id"] == call_id
            assert b"owner@example.com" not in request.content
        return httpx.Response(
            200,
            json={
                "id": response_id,
                "object": "response",
                "status": "completed",
                "output": [
                    {
                        "id": function_id,
                        "type": "function_call",
                        "status": "completed",
                        "call_id": call_id,
                        "name": "lookup",
                        "arguments": "{}",
                    }
                ],
            },
        )

    upstream = LLMClient(
        "https://provider.invalid/v1", "synthetic", transport=httpx.MockTransport(provider)
    )
    client = TestClient(create_app(replace(settings, llm_provider="openai"), llm_client=upstream))
    first = client.post("/v1/responses", json={"model": "test", "input": "Find customer"})
    assert first.status_code == 200
    item = first.json()["output"][0]
    assert (first.json()["id"], item["id"], item["call_id"]) == (response_id, function_id, call_id)
    second = client.post(
        "/v1/responses",
        json={
            "model": "test",
            "input": [
                {key: item[key] for key in ("type", "call_id", "name", "arguments")},
                {
                    "type": "function_call_output",
                    "call_id": item["call_id"],
                    "output": "owner@example.com",
                },
            ],
        },
    )
    assert second.status_code == 200
    assert len(bodies) == 2
