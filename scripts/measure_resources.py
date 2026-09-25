"""Measure a bounded local synthetic MaskGate workload without provider traffic."""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.proxy.llm_client import UpstreamResult  # noqa: E402


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("page_fault_count", ctypes.c_ulong),
        ("peak_working_set_size", ctypes.c_size_t),
        ("working_set_size", ctypes.c_size_t),
        ("quota_peak_paged_pool_usage", ctypes.c_size_t),
        ("quota_paged_pool_usage", ctypes.c_size_t),
        ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
        ("quota_non_paged_pool_usage", ctypes.c_size_t),
        ("pagefile_usage", ctypes.c_size_t),
        ("peak_pagefile_usage", ctypes.c_size_t),
    ]


def _rss_bytes() -> int:
    if os.name != "nt":
        raise RuntimeError("this evidence script currently measures Windows RSS only")
    counters = _ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    psapi.GetProcessMemoryInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_ProcessMemoryCounters),
        ctypes.c_ulong,
    ]
    psapi.GetProcessMemoryInfo.restype = ctypes.c_int
    process = kernel32.GetCurrentProcess()
    if not psapi.GetProcessMemoryInfo(
        process,
        ctypes.byref(counters),
        counters.cb,
    ):
        raise OSError("GetProcessMemoryInfo failed")
    return int(counters.working_set_size)


class _SyntheticUpstream:
    async def complete(self, payload: dict[str, Any]) -> UpstreamResult:
        await asyncio.sleep(0.02)
        return UpstreamResult(
            200,
            {
                "id": "chatcmpl-resource-measurement",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Synthetic response"},
                    }
                ],
            },
        )


def _settings() -> Settings:
    return Settings(
        app_env="test",
        app_host="127.0.0.1",
        app_port=8080,
        llm_provider="mock",
        llm_base_url="https://mock.invalid/v1",
        llm_api_key="synthetic-key",
        llm_default_model="test-model",
        gemini_base_url="https://mock.invalid/v1beta",
        gemini_api_key="synthetic-key",
        gemini_model="gemini-test",
        upstream_timeout_seconds=5,
        masking_mode="placeholder",
        mapping_ttl_seconds=60,
        conversation_ttl_seconds=60,
        conversation_max_messages=40,
        conversation_max_chars=120_000,
        public_email_allowlist=(),
        public_email_domain_allowlist=(),
        public_person_allowlist=(),
        enable_debug_endpoints=False,
        log_level="WARNING",
        block_api_keys=True,
        block_secrets=True,
        block_credit_cards=False,
        enable_playground=False,
        policy_file=ROOT / "app" / "policies" / "default_policy.yaml",
        admission_global_max_operations=4,
        admission_principal_max_operations=4,
    )


def main() -> int:
    requests = 12
    concurrency = 4
    payload_bytes = 64 * 1024
    app = create_app(_settings(), llm_client=_SyntheticUpstream())
    sample_stop = threading.Event()
    samples: list[int] = []

    def sample() -> None:
        while not sample_stop.wait(0.005):
            samples.append(_rss_bytes())

    with TestClient(app) as client:
        warmup = client.post(
            "/v1/chat/completions",
            json={"model": "test-model", "messages": [{"role": "user", "content": "warmup"}]},
        )
        if warmup.status_code != 200:
            raise RuntimeError("synthetic warmup failed")
        baseline = _rss_bytes()
        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [
                executor.submit(
                    client.post,
                    "/v1/chat/completions",
                    json={
                        "model": "test-model",
                        "messages": [
                            {
                                "role": "user",
                                "content": ("ordinary synthetic text " * 3_000)[
                                    :payload_bytes
                                ],
                            }
                        ],
                    },
                )
                for _ in range(requests)
            ]
            responses = [future.result() for future in futures]
        elapsed = time.perf_counter() - started
        sample_stop.set()
        sampler.join(timeout=1)
        samples.append(_rss_bytes())

    if any(response.status_code != 200 for response in responses):
        raise RuntimeError("synthetic request failed")
    snapshot = app.state.admission.snapshot()
    if snapshot["active_operations"] or snapshot["reserved_bytes"]:
        raise RuntimeError("admission reservations were not released")
    peak = max(samples, default=baseline)
    print(
        json.dumps(
            {
                "platform": "windows",
                "requests": requests,
                "concurrency": concurrency,
                "payload_bytes_each": payload_bytes,
                "elapsed_seconds": round(elapsed, 3),
                "baseline_rss_bytes": baseline,
                "peak_rss_bytes": peak,
                "peak_delta_bytes": max(peak - baseline, 0),
                "final_admission": snapshot,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
