import pytest

from app.observability import PrivacyMetric, PrivacyMetrics, PrivacyStage


def test_metrics_record_only_bounded_taxonomy_labels() -> None:
    metrics = PrivacyMetrics()
    metrics.increment(PrivacyMetric.DETECTIONS, taxonomy_label="email", amount=2)
    metrics.increment(PrivacyMetric.POLICY_BLOCKS)
    metrics.observe(PrivacyStage.DETECTION, 0.0125)

    assert metrics.snapshot() == {
        "counters": {
            "detections_total:EMAIL": 2,
            "policy_blocks_total": 1,
        },
        "latencies": {
            "detection": {"count": 1, "total_ms": 12.5, "maximum_ms": 12.5}
        },
    }


@pytest.mark.parametrize(
    "raw_value",
    [
        "person@example.com",
        "Bearer secret",
        "user supplied label",
        "A" * 65,
        "../../private",
    ],
)
def test_metrics_reject_raw_or_unbounded_labels(raw_value: str) -> None:
    with pytest.raises(ValueError):
        PrivacyMetrics().increment(PrivacyMetric.DETECTIONS, taxonomy_label=raw_value)


def test_metric_label_cardinality_is_bounded() -> None:
    metrics = PrivacyMetrics(max_labels_per_metric=1)
    metrics.increment(PrivacyMetric.DETECTIONS, taxonomy_label="EMAIL")
    metrics.increment(PrivacyMetric.DETECTIONS, taxonomy_label="PHONE")

    assert metrics.snapshot()["counters"] == {
        "detections_total:EMAIL": 1,
        "detections_total:OTHER": 1,
    }
