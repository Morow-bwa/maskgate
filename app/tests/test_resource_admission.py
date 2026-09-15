from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from typing import Any

from fastapi.testclient import TestClient

from app.main import create_app
from app.proxy.llm_client import UpstreamResult


def _success() -> dict[str, Any]:
    return {
        "id": "chatcmpl-capacity",
        "object": "chat.completion",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "Safe"}}
        ],
    }


class BlockingUpstream:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.payloads: list[dict[str, Any]] = []

    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        self.payloads.append(deepcopy(payload))
        if len(self.payloads) == 1:
            self.started.set()
            await asyncio.to_thread(self.release.wait)
        return UpstreamResult(200, _success())


class SlowUpstream:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        self.calls += 1
        await asyncio.sleep(0.2)
        return UpstreamResult(200, _success())

    async def aclose(self) -> None:
        return None


class ImmediateUpstream:
    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        return UpstreamResult(200, _success())


class SlowStreamingUpstream:
    def __init__(self) -> None:
        self.cancelled = False
        self.closed = False

    async def complete_stream(self, payload: dict[str, Any]):
        try:
            for content in ("one", "two", "three"):
                await asyncio.sleep(0.04)
                yield {
                    "id": "chatcmpl-deadline",
                    "object": "chat.completion.chunk",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": content},
                            "finish_reason": None,
                        }
                    ],
                }
        finally:
            self.cancelled = True

    async def aclose(self) -> None:
        self.closed = True


def test_global_admission_rejects_before_a_second_provider_call_and_releases(settings) -> None:
    upstream = BlockingUpstream()
    limited = replace(settings, admission_global_max_operations=1)
    app = create_app(limited, llm_client=upstream)

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(
            client.post,
            "/v1/chat/completions",
            json={"model": "test-model", "messages": [{"role": "user", "content": "Hold"}]},
        )
        assert upstream.started.wait(timeout=2)

        rejected = client.post(
            "/v1/chat/completions",
            json={"model": "test-model", "messages": [{"role": "user", "content": "Reject"}]},
        )
        assert rejected.status_code == 503
        assert rejected.json()["error"]["type"] == "global_capacity_exceeded"
        assert len(upstream.payloads) == 1

        upstream.release.set()
        assert pending.result(timeout=2).status_code == 200

    assert app.state.admission.snapshot()["active_operations"] == 0
    assert app.state.admission.snapshot()["reserved_bytes"] == 0
    assert app.state.privacy_metrics.snapshot()["counters"][
        "admission_rejections_total:GLOBAL"
    ] == 1


def test_principal_admission_isolated_under_concurrent_load(settings) -> None:
    upstream = BlockingUpstream()
    limited = replace(
        settings,
        require_auth=True,
        api_keys=("tenant-a-key", "tenant-b-key"),
        admission_global_max_operations=2,
        admission_principal_max_operations=1,
    )
    app = create_app(limited, llm_client=upstream)
    headers_a = {"Authorization": "Bearer tenant-a-key"}
    headers_b = {"Authorization": "Bearer tenant-b-key"}

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(
            client.post,
            "/v1/chat/completions",
            headers=headers_a,
            json={"model": "test-model", "messages": [{"role": "user", "content": "Hold"}]},
        )
        assert upstream.started.wait(timeout=2)

        same_principal = client.post(
            "/v1/chat/completions",
            headers=headers_a,
            json={"model": "test-model", "messages": []},
        )
        other_principal = client.post(
            "/v1/chat/completions",
            headers=headers_b,
            json={"model": "test-model", "messages": []},
        )

        assert same_principal.status_code == 429
        assert same_principal.json()["error"]["type"] == "principal_capacity_exceeded"
        assert other_principal.status_code == 200
        assert len(upstream.payloads) == 2
        upstream.release.set()
        assert pending.result(timeout=2).status_code == 200

    assert app.state.admission.snapshot()["active_principals"] == 0


def test_total_operation_deadline_cancels_provider_and_releases_resources(settings) -> None:
    upstream = SlowUpstream()
    limited = replace(settings, operation_timeout_seconds=0.05)
    app = create_app(limited, llm_client=upstream)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "test-model",
                "conversation_id": "deadline-conversation-1",
                "messages": [{"role": "user", "content": "Slow"}],
            },
        )

    assert response.status_code == 504
    assert response.json()["error"]["type"] == "operation_timeout"
    assert upstream.calls == 1
    assert app.state.mapping_store.size() == 0
    state = next(iter(app.state.conversation_store._items.values()))
    assert not state.lock.locked()
    assert state.lease_count == 0
    assert app.state.admission.snapshot()["active_operations"] == 0
    assert app.state.privacy_metrics.snapshot()["counters"]["operation_timeouts_total"] == 1


def test_conversation_memory_exhaustion_is_a_bounded_public_error(settings) -> None:
    upstream = SlowUpstream()
    limited = replace(
        settings,
        conversation_global_max_bytes=1_024,
        conversation_principal_max_bytes=1_024,
        operation_timeout_seconds=1,
    )
    app = create_app(limited, llm_client=upstream)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "test-model",
                "conversation_id": "bounded-history-1",
                "messages": [
                    {"role": "user", "content": "ordinary synthetic text " * 100}
                ],
            },
        )

    assert response.status_code == 503, response.text
    assert response.json()["error"] == {
        "message": "Conversation memory capacity is temporarily exhausted",
        "type": "conversation_memory_capacity_exceeded",
    }
    assert upstream.calls == 0
    state = next(iter(app.state.conversation_store._items.values()))
    assert state.messages == []
    assert state.accounted_bytes == 0
    assert state.lease_count == 0
    assert app.state.conversation_store.snapshot()["reserved_publish_bytes"] == 0


def test_total_deadline_stops_a_stream_even_when_chunks_keep_arriving(settings) -> None:
    upstream = SlowStreamingUpstream()
    limited = replace(settings, operation_timeout_seconds=0.09)
    app = create_app(limited, llm_client=upstream)

    with TestClient(app) as client:
        with client.stream(
            "POST",
            "/v1/chat/completions",
            json={
                "model": "test-model",
                "stream": True,
                "messages": [{"role": "user", "content": "Slow stream"}],
            },
        ) as response:
            body = response.read().decode()

        assert response.status_code == 200
        assert "data: [DONE]" not in body
        assert upstream.cancelled is True
        assert app.state.admission.snapshot()["active_operations"] == 0

    assert upstream.closed is True
    assert app.state.admission.snapshot()["draining"] is True


def test_debug_metrics_export_only_fixed_aggregate_dimensions(settings) -> None:
    app = create_app(settings, llm_client=SlowUpstream())

    with TestClient(app) as client:
        response = client.get("/debug/metrics")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert set(response.json()) == {
        "privacy",
        "admission",
        "conversation_state",
        "request_mappings",
    }
    assert set(response.json()["admission"]) == {
        "active_operations",
        "reserved_bytes",
        "active_principals",
        "draining",
    }
    assert set(response.json()["conversation_state"]) == {
        "conversations",
        "active_leases",
        "retained_bytes",
        "reserved_publish_bytes",
    }


def test_output_guard_exception_records_a_failure_not_a_redaction(settings, monkeypatch) -> None:
    app = create_app(settings, llm_client=ImmediateUpstream())

    def fail_output(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("synthetic output transform failure")

    monkeypatch.setattr(
        app.state.chat_orchestrator._privacy_pipeline.output_guard,
        "process",
        fail_output,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={"model": "test-model", "messages": [{"role": "user", "content": "Safe"}]},
        )

    assert response.status_code == 502
    counters = app.state.privacy_metrics.snapshot()["counters"]
    assert counters["output_failures_total"] == 1
    assert "output_redactions_total" not in counters
