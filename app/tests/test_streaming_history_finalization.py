from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.masking.anonymizer import MappingItem
from app.privacy.detection import DetectorEnsemble
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.pipeline import ProviderOutputViolation
from app.proxy.llm_client import LLMClient
from app.proxy.streaming import BufferedStreamingOutputGuard
from app.tests.test_chat_orchestrator_fail_closed import RecordingUpstream


class NewPersonalDataUpstream(RecordingUpstream):
    async def complete_stream(self, payload):
        self.stream_payloads.append(payload)
        for text in ("Contact synthetic.person@", "example.net"):
            yield {"choices": [{"index": 0, "delta": {"content": text}}]}
        yield {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}


class ToolHistoryUpstream(RecordingUpstream):
    async def complete_stream(self, payload):
        self.stream_payloads.append(payload)
        yield _event(
            0,
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "call_retained_1",
                        "type": "function",
                        "function": {"name": "inspect", "arguments": '{"value":"safe"}'},
                    }
                ]
            },
            "tool_calls",
        )


def test_new_provider_pii_is_absent_from_history_and_next_turn(settings):
    upstream = NewPersonalDataUpstream()
    app = create_app(settings, llm_client=upstream)
    client = TestClient(app)
    body = {
        "model": "test-model",
        "conversation_id": "history-regression",
        "messages": [{"role": "user", "content": "Hello"}],
        "stream": True,
    }
    response = client.post("/v1/chat/completions", json=body)
    assert "synthetic.person@example.net" not in response.text
    states = list(app.state.conversation_store._items.values())
    assert len(states) == 1
    assert "synthetic.person@example.net" not in json.dumps(states[0].messages)
    body["stream"] = False
    response = client.post("/v1/chat/completions", json=body)
    assert response.status_code == 200
    assert len(upstream.complete_payloads) == 1


def test_retained_tool_call_and_followup_result_replay_on_second_turn(settings):
    upstream = ToolHistoryUpstream()
    client = TestClient(create_app(settings, llm_client=upstream))
    conversation_id = "tool-history-replay"

    streamed = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [{"role": "user", "content": "Call the tool"}],
            "stream": True,
        },
    )
    continued = client.post(
        "/v1/chat/completions",
        json={
            "model": "test-model",
            "conversation_id": conversation_id,
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call_retained_1",
                    "content": '{"result":"ok"}',
                }
            ],
        },
    )

    assert streamed.status_code == 200
    assert "data: [DONE]" in streamed.text
    assert continued.status_code == 200
    replay = upstream.complete_payloads[0]["messages"]
    assert any(
        message.get("role") == "assistant"
        and message["tool_calls"][0]["id"] == "call_retained_1"
        for message in replay
    )
    assert replay[-1]["tool_call_id"] == "call_retained_1"


def test_provider_eof_after_finished_choices_is_an_accepted_transport_termination(settings):
    sse = (
        'data: {"choices":[{"index":0,"delta":{"content":"Safe"}}]}\n\n'
        'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
    )

    def provider(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=sse,
            headers={"content-type": "text/event-stream"},
            request=request,
        )

    upstream = LLMClient(
        "https://provider.invalid/v1",
        "synthetic-test-key",
        transport=httpx.MockTransport(provider),
    )
    response = TestClient(create_app(settings, llm_client=upstream)).post(
        "/v1/chat/completions",
        json={"model": "test-model", "messages": [], "stream": True},
    )

    assert response.status_code == 200
    assert "Safe" in response.text
    assert "data: [DONE]" in response.text


def test_finish_marker_follows_buffered_content(settings):
    client = TestClient(create_app(settings, llm_client=NewPersonalDataUpstream()))
    response = client.post("/v1/chat/completions", json={
        "model": "test-model", "stream": True,
        "messages": [{"role": "user", "content": "Hello"}],
    })
    events = [json.loads(line[6:]) for line in response.text.splitlines()
              if line.startswith("data: ") and line != "data: [DONE]"]
    content_position = next(i for i, e in enumerate(events)
                            if "REDACTED_PROVIDER" in json.dumps(e))
    finish_position = next(i for i, e in enumerate(events)
                           if any(c.get("finish_reason") for c in e.get("choices", [])))
    assert content_position < finish_position


def _guard(mapping=None):
    return BufferedStreamingOutputGuard(OutputPrivacyGuard(DetectorEnsemble()), mapping or [])


def _conversation_guard(mapping=None):
    return BufferedStreamingOutputGuard(
        OutputPrivacyGuard(DetectorEnsemble()),
        mapping or [],
        require_replayable_history=True,
    )


def _event(index, delta=None, finish=None):
    return {"choices": [{"index": index, "delta": delta or {}, "finish_reason": finish}]}


def test_sparse_reordered_choices_keep_semantic_identity_and_history_choice_zero():
    guard = _guard()
    guard.push(_event(9, {"content": "Other "}))
    guard.push(_event(0, {"content": "Primary "}))
    guard.push({"choices": [
        {"index": 0, "delta": {"content": "answer"}, "finish_reason": "stop"},
        {"index": 9, "delta": {"content": "answer"}, "finish_reason": "stop"},
    ]})
    result = guard.finalize()
    assert result.history_message == {"role": "assistant", "content": "Primary answer"}
    content = {c["index"]: c["delta"]["content"] for e in result.events[:-1]
               for c in e["choices"]}
    assert content == {9: "Other answer", 0: "Primary answer"}


def test_sparse_tools_keep_ids_names_and_fragmented_arguments_separate():
    guard = _guard()
    for index, call_id, argument in [(7, "call_seven", '{"value":"seven'),
                                     (2, "call_two", '{"value":"two')]:
        guard.push(_event(0, {"tool_calls": [
            {"index": index, "id": call_id, "type": "function",
             "function": {"name": "inspect", "arguments": argument}},
        ]}))
    guard.push(_event(0, {"tool_calls": [
        {"index": 2, "function": {"arguments": '"}'}},
        {"index": 7, "function": {"arguments": '"}'}},
    ]}, "tool_calls"))
    result = guard.finalize()
    tools = result.history_message["tool_calls"]
    assert [t["id"] for t in tools] == ["call_two", "call_seven"]
    assert [json.loads(t["function"]["arguments"])["value"] for t in tools] == ["two", "seven"]
    assert all("index" not in t for t in tools)
    client_tools = result.events[0]["choices"][0]["delta"]["tool_calls"]
    assert [t["index"] for t in client_tools] == [2, 7]


def test_authorized_original_is_client_only_and_history_keeps_token():
    token = "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"
    guard = _guard([MappingItem("EMAIL", "owner@example.com", token)])
    guard.push(_event(0, {"content": token[:15]}))
    guard.push(_event(0, {"content": token[15:]}, "stop"))
    result = guard.finalize()
    assert result.history_message["content"] == token
    assert result.events[0]["choices"][0]["delta"]["content"] == "owner@example.com"


@pytest.mark.parametrize("field", ["refusal", "function_call"])
def test_structured_history_is_inspected_and_preserved(field):
    guard = _guard()
    for fragment in ("synthetic.person@", "example.net"):
        delta = {field: fragment if field == "refusal" else {"arguments": fragment}}
        guard.push(_event(0, delta))
    if field == "function_call":
        guard.push(_event(0, {field: {"name": "inspect"}}))
    guard.push(_event(0, finish="stop"))
    result = guard.finalize()
    assert field in result.history_message
    assert "synthetic.person@example.net" not in json.dumps(result.history_message)
    assert "REDACTED_PROVIDER" in json.dumps(result.history_message)


@pytest.mark.parametrize("event", [
    {"error": {"message": "untrusted error"}},
    _event(-1), _event(True), _event(0, finish=[]),
    {"choices": [{"index": 0}, {"index": 0}]},
    _event(0, {"tool_calls": [{"index": -1}]}),
    _event(0, {"tool_calls": [{"index": 1}, {"index": 1}]}),
])
def test_invalid_stream_state_fails_closed(event):
    with pytest.raises(ProviderOutputViolation):
        _guard().push(event)


def test_missing_terminal_rejects_and_clears_accumulators():
    guard = _guard()
    guard.push(_event(0, {"content": "unfinished"}))
    with pytest.raises(ProviderOutputViolation):
        guard.finalize()
    assert guard._messages == {}
    with pytest.raises(ProviderOutputViolation):
        guard.push(_event(0))


def test_post_finish_data_is_rejected():
    guard = _guard()
    guard.push(_event(0, {"content": "finished"}, "stop"))
    with pytest.raises(ProviderOutputViolation):
        guard.push(_event(0, {"content": "late"}))


def test_refusal_history_is_explicitly_normalized_for_supported_replay():
    guard = _conversation_guard()
    guard.push(_event(0, {"refusal": "Request declined"}, "content_filter"))

    result = guard.finalize()

    assert result.history_message == {"role": "assistant", "content": "Request declined"}
    assert result.events[0]["choices"][0]["delta"]["refusal"] == "Request declined"


def test_legacy_function_call_is_rejected_before_conversation_retention():
    guard = _conversation_guard()
    guard.push(
        _event(
            0,
            {"function_call": {"name": "inspect", "arguments": "{}"}},
            "function_call",
        )
    )

    with pytest.raises(ProviderOutputViolation):
        guard.finalize()


@pytest.mark.parametrize("arguments", ['{"value":', "[]", "null"])
def test_non_object_or_partial_tool_arguments_reject_replay(arguments):
    guard = _conversation_guard()
    guard.push(
        _event(
            0,
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "call_test",
                        "type": "function",
                        "function": {"name": "inspect", "arguments": arguments},
                    }
                ]
            },
            "tool_calls",
        )
    )

    with pytest.raises(ProviderOutputViolation):
        guard.finalize()


def test_conversation_stream_without_choice_zero_rejects_before_commit():
    guard = _conversation_guard()
    guard.push(_event(7, {"content": "Alternative"}, "stop"))

    with pytest.raises(ProviderOutputViolation):
        guard.finalize()


def test_request_stream_without_choice_zero_remains_supported():
    guard = _guard()
    guard.push(_event(7, {"content": "Alternative"}, "stop"))

    result = guard.finalize()

    assert result.history_message is None
    assert result.events[0]["choices"][0]["index"] == 7


class UnfinishedUpstream(RecordingUpstream):
    async def complete_stream(self, payload):
        yield _event(0, {"content": "unfinished"})


def test_truncated_stream_has_no_done_marker_or_committed_history(settings):
    app = create_app(settings, llm_client=UnfinishedUpstream())
    response = TestClient(app).post("/v1/chat/completions", json={
        "model": "test-model", "stream": True, "conversation_id": "unfinished-history",
        "messages": [{"role": "user", "content": "Hello"}],
    })
    assert "upstream_invalid_stream" in response.text
    assert "data: [DONE]" not in response.text
    assert "unfinished" not in response.text
    state = next(iter(app.state.conversation_store._items.values()))
    assert state.messages == []
    assert not state.lock.locked()
