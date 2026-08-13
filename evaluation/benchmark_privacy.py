from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Callable

from app.identity import PrincipalContext
from app.masking.anonymizer import MaskingSession
from app.observability import PrivacyMetrics
from app.policies.policy_engine import PolicyEngine
from app.privacy.detection import CanonicalText, DetectorEnsemble, LegacyEntityDetectorAdapter
from app.privacy.models import DetectorProfile, TokenScope
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.policy import LegacyPolicyAdapter, PolicyEngineV2
from app.privacy.risk import PrivacyRiskEngine
from app.privacy.runtime import PrivacyRequestContext, PrivacyRuntime
from app.privacy.wire import FinalWirePrivacyGuard

SYNTHETIC_TEXT = "Please contact synthetic.user@example.org or +1 202 555 0147 about the fixture."


def _measure(operation: Callable[[], object], iterations: int) -> dict[str, float]:
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        operation()
        samples.append((time.perf_counter() - started) * 1000)
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, round((len(ordered) - 1) * 0.95))
    return {
        "mean_ms": round(statistics.fmean(samples), 4),
        "p95_ms": round(ordered[p95_index], 4),
        "maximum_ms": round(max(samples), 4),
    }


def benchmark(iterations: int) -> dict[str, object]:
    policy_path = Path(__file__).parents[1] / "app" / "policies" / "default_policy.yaml"
    legacy_policy = PolicyEngine(policy_path)
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
    adapter = LegacyEntityDetectorAdapter(detector)
    detections = detector.detect(SYNTHETIC_TEXT)
    risk_engine = PrivacyRiskEngine()
    policy_v2 = PolicyEngineV2(LegacyPolicyAdapter().adapt(legacy_policy.rules))
    metrics = PrivacyMetrics()
    runtime = PrivacyRuntime(detector, risk_engine, policy_v2, metrics)
    principal = PrincipalContext("benchmark", "maskgate", "synthetic", "local")
    request = PrivacyRequestContext(
        route="/benchmark",
        provider="openai",
        model="synthetic-model",
        jurisdiction="unspecified",
        purpose="performance_test",
        token_scope=TokenScope.REQUEST,
    )

    def transform() -> object:
        session = MaskingSession("placeholder", legacy_policy)
        return runtime.transform_text(
            SYNTHETIC_TEXT,
            session=session,
            principal=principal,
            request=request,
            json_path=("messages", 0, "content"),
            role="user",
        )

    transformed = transform()
    session = MaskingSession("placeholder", legacy_policy)
    transformed_for_wire = runtime.transform_text(
        SYNTHETIC_TEXT,
        session=session,
        principal=principal,
        request=request,
        json_path=("messages", 0, "content"),
        role="user",
    )
    guard = FinalWirePrivacyGuard(adapter)

    def wire_check() -> object:
        return guard.check(
            provider="openai-chat-completions",
            target="/chat/completions",
            payload={
                "model": "synthetic-model",
                "messages": [{"role": "user", "content": transformed_for_wire.text}],
                "store": False,
            },
            approved_tokens={item.replacement for item in session.items},
        )

    output_guard = OutputPrivacyGuard(adapter)

    return {
        "iterations": iterations,
        "synthetic_input_chars": len(SYNTHETIC_TEXT),
        "stages": {
            "canonicalization": _measure(
                lambda: CanonicalText.from_text(SYNTHETIC_TEXT), iterations
            ),
            "detection_including_canonicalization": _measure(
                lambda: detector.detect(SYNTHETIC_TEXT), iterations
            ),
            "risk": _measure(lambda: risk_engine.assess(detections), iterations),
            "detection_risk_policy_tokenization": _measure(transform, iterations),
            "wire_guard": _measure(wire_check, iterations),
            "output_guard": _measure(
                lambda: output_guard.process(
                    {
                        "choices": [
                            {
                                "message": {
                                    "role": "assistant",
                                    "content": transformed_for_wire.text,
                                }
                            }
                        ]
                    },
                    session.items,
                ),
                iterations,
            ),
        },
        "detected_entities": len(detections),
        "transformed_chars": len(transformed.text),
        "note": "Synthetic local benchmark; not a production SLA or detector-quality metric.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark local MaskGate privacy stages")
    parser.add_argument("--iterations", type=int, default=200)
    args = parser.parse_args()
    if args.iterations < 1:
        raise SystemExit("--iterations must be positive")
    print(json.dumps(benchmark(args.iterations), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
