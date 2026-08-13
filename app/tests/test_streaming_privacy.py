from __future__ import annotations

from app.masking.anonymizer import MappingItem
from app.privacy.detection import DetectorEnsemble
from app.privacy.models import DetectorProfile
from app.privacy.output_guard import OutputPrivacyGuard
from app.proxy.streaming import BufferedStreamingOutputGuard

TOKEN = "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"


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
                            {"index": 0, "function": {"arguments": '{"email":"stranger@'}}
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
        events = guard.finish_events()
        assert events[0]["choices"][0]["delta"]["content"] == "owner@example.com"
