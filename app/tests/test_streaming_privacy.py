from __future__ import annotations

import base64
import json

import pytest

from app.masking.anonymizer import MappingItem
from app.privacy.detection import DetectorEnsemble
from app.privacy.models import DetectorProfile
from app.privacy.output_guard import OutputPrivacyGuard
from app.proxy.streaming import BufferedStreamingOutputGuard

TOKEN = "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"


def _finish(guard, *indexes):
    guard.push({"choices": [
        {"index": index, "delta": {}, "finish_reason": "stop"} for index in indexes
    ]})


def _jwt() -> str:
    parts = [{"alg": "HS256"}, {"email": "owner@example.com"}]
    return (
        ".".join(
            base64.urlsafe_b64encode(json.dumps(part).encode()).decode().rstrip("=")
            for part in parts
        )
        + "."
        + "synthetic" * 4
    )


@pytest.mark.parametrize(
    "sensitive",
    ["GB82WEST12345698765432", _jwt(), "split.owner@example.com"],
    ids=["iban", "jwt", "provider-email"],
)
@pytest.mark.parametrize("tool", [False, True], ids=["text", "tool"])
def test_fragmented_sensitive_values_never_escape_streaming(sensitive, tool) -> None:
    for split in range(1, len(sensitive)):
        guard = BufferedStreamingOutputGuard(
            OutputPrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT)), []
        )
        for fragment in (sensitive[:split], sensitive[split:]):
            delta = (
                {"tool_calls": [{"index": 0, "function": {"arguments": fragment}}]}
                if tool
                else {"content": fragment}
            )
            event = guard.push({"choices": [{"index": 0, "delta": delta}]})
            emitted = event["choices"][0]["delta"]
            assert (
                emitted["tool_calls"][0]["function"]["arguments"] if tool else emitted["content"]
            ) == ""
        if tool:
            guard.push({"choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "id": "call_test", "type": "function",
                 "function": {"name": "inspect"}}
            ]}}]})
        _finish(guard, 0)
        output = json.dumps(guard.finish_events())
        assert sensitive not in output
        assert "REDACTED_PROVIDER" in output


def test_streaming_buffers_all_choices_and_tool_arguments_until_inspected() -> None:
    mapping = [MappingItem("EMAIL", "owner@example.com", TOKEN)]
    guard = BufferedStreamingOutputGuard(
        OutputPrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT)), mapping
    )

    first = guard.push(
        {
            "choices": [
                {"index": 0, "delta": {"content": TOKEN[:12]}},
                {
                    "index": 1,
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "id": "call_test", "type": "function",
                             "function": {"name": "inspect", "arguments": '{"email":"stranger@'}}
                        ]
                    },
                },
            ]
        }
    )
    second = guard.push(
        {
            "choices": [
                {"index": 0, "delta": {"content": TOKEN[12:]}},
                {
                    "index": 1,
                    "delta": {
                        "tool_calls": [{"index": 0, "function": {"arguments": 'example.net"}'}}]
                    },
                },
            ]
        }
    )

    assert first["choices"][0]["delta"]["content"] == ""
    assert second["choices"][0]["delta"]["content"] == ""
    _finish(guard, 0, 1)
    finished = guard.finish_events()
    assert finished[0]["choices"][0]["delta"]["content"] == "owner@example.com"
    assert "stranger@example.net" not in str(finished)
    assert "[REDACTED_PROVIDER_EMAIL]" in str(finished)


def test_streaming_restores_opaque_token_at_every_split_boundary() -> None:
    mapping = [MappingItem("EMAIL", "owner@example.com", TOKEN)]

    for split in range(1, len(TOKEN)):
        guard = BufferedStreamingOutputGuard(
            OutputPrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT)), mapping
        )
        guard.push({"choices": [{"index": 0, "delta": {"content": TOKEN[:split]}}]})
        guard.push({"choices": [{"index": 0, "delta": {"content": TOKEN[split:]}}]})
        _finish(guard, 0)
        events = guard.finish_events()
        assert events[0]["choices"][0]["delta"]["content"] == "owner@example.com"


@pytest.mark.parametrize("field", ["id", "name"])
def test_streaming_buffers_sensitive_tool_metadata_at_every_split_boundary(field: str) -> None:
    sensitive = "metadata.owner@example.com"
    for split in range(1, len(sensitive)):
        guard = BufferedStreamingOutputGuard(
            OutputPrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT)),
            [],
        )
        first_value, second_value = sensitive[:split], sensitive[split:]
        first_tool = {
            "index": 0,
            "type": "function",
            "function": {"arguments": "{}"},
        }
        second_tool = {"index": 0, "function": {}}
        if field == "id":
            first_tool["id"] = first_value
            second_tool["id"] = second_value
            first_tool["function"]["name"] = "inspect"
        else:
            first_tool["id"] = "call_test"
            first_tool["function"]["name"] = first_value
            second_tool["function"]["name"] = second_value
        guard.push({"choices": [{"index": 0, "delta": {"tool_calls": [first_tool]}}]})
        guard.push({"choices": [{"index": 0, "delta": {"tool_calls": [second_tool]}}]})
        _finish(guard, 0)

        output = json.dumps(guard.finish_events())
        assert sensitive not in output
        assert "REDACTED_PROVIDER" in output
