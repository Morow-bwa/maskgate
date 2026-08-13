from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from enum import StrEnum

_SAFE_LABEL = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


class PrivacyMetric(StrEnum):
    DETECTIONS = "detections_total"
    POLICY_BLOCKS = "policy_blocks_total"
    POLICY_REVIEWS = "policy_reviews_total"
    PROVIDER_TRANSFORM_FAILURES = "provider_transform_failures_total"
    WIRE_REJECTIONS = "wire_rejections_total"
    OUTPUT_REDACTIONS = "output_redactions_total"
    VAULT_INSERTS = "vault_inserts_total"
    VAULT_DELETIONS = "vault_deletions_total"
    VAULT_CAPACITY_REJECTIONS = "vault_capacity_rejections_total"


class PrivacyStage(StrEnum):
    CANONICALIZATION = "canonicalization"
    DETECTION = "detection"
    RISK = "risk"
    POLICY = "policy"
    TOKENIZATION = "tokenization"
    PROVIDER_ADAPTER = "provider_adapter"
    WIRE_GUARD = "wire_guard"
    OUTPUT_GUARD = "output_guard"
    STREAMING = "streaming"
    MEDIA = "media"


@dataclass(slots=True)
class _Latency:
    count: int = 0
    total_ms: float = 0.0
    maximum_ms: float = 0.0


class PrivacyMetrics:
    """Bounded in-memory metrics Implementation with no raw-data arguments.

    Labels are taxonomy identifiers such as ``EMAIL`` or ``AUTH_SECRET``.
    Arbitrary values, prompts, credentials, paths, model IDs, and mappings are
    intentionally absent from this Interface.
    """

    def __init__(self, *, max_labels_per_metric: int = 256) -> None:
        self._max_labels_per_metric = max(max_labels_per_metric, 1)
        self._counters: dict[tuple[PrivacyMetric, str | None], int] = {}
        self._latencies: dict[PrivacyStage, _Latency] = {}
        self._lock = threading.Lock()

    def increment(
        self,
        metric: PrivacyMetric,
        *,
        taxonomy_label: str | None = None,
        amount: int = 1,
    ) -> None:
        if not isinstance(metric, PrivacyMetric):
            raise TypeError("metric must be PrivacyMetric")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
            raise ValueError("metric amount must be a positive integer")
        label = self._validate_label(taxonomy_label)
        key = (metric, label)
        with self._lock:
            if key not in self._counters:
                distinct_labels = sum(
                    1
                    for existing_metric, existing_label in self._counters
                    if existing_metric is metric and existing_label is not None
                )
                if label is not None and distinct_labels >= self._max_labels_per_metric:
                    label = "OTHER"
                    key = (metric, label)
            self._counters[key] = self._counters.get(key, 0) + amount

    def observe(self, stage: PrivacyStage, elapsed_seconds: float) -> None:
        if not isinstance(stage, PrivacyStage):
            raise TypeError("stage must be PrivacyStage")
        if isinstance(elapsed_seconds, bool) or elapsed_seconds < 0:
            raise ValueError("elapsed_seconds must be non-negative")
        milliseconds = float(elapsed_seconds) * 1000.0
        with self._lock:
            latency = self._latencies.setdefault(stage, _Latency())
            latency.count += 1
            latency.total_ms += milliseconds
            latency.maximum_ms = max(latency.maximum_ms, milliseconds)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            counters = {
                self._counter_name(metric, label): count
                for (metric, label), count in sorted(
                    self._counters.items(), key=lambda item: (item[0][0].value, item[0][1] or "")
                )
            }
            latencies = {
                stage.value: {
                    "count": latency.count,
                    "total_ms": round(latency.total_ms, 3),
                    "maximum_ms": round(latency.maximum_ms, 3),
                }
                for stage, latency in sorted(
                    self._latencies.items(), key=lambda item: item[0].value
                )
            }
        return {"counters": counters, "latencies": latencies}

    @staticmethod
    def _validate_label(label: str | None) -> str | None:
        if label is None:
            return None
        normalized = label.strip().upper()
        if not _SAFE_LABEL.fullmatch(normalized):
            raise ValueError("taxonomy_label must be a bounded taxonomy identifier")
        return normalized

    @staticmethod
    def _counter_name(metric: PrivacyMetric, label: str | None) -> str:
        return metric.value if label is None else f"{metric.value}:{label}"
