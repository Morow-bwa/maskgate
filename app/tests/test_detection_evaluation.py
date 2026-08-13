from __future__ import annotations

import json
from pathlib import Path

from app.privacy.detection import DetectorEnsemble
from app.privacy.models import DetectorProfile
from evaluation.evaluate_detection import evaluate, load_corpus

CORPUS_ROOT = Path(__file__).parents[2] / "evaluation" / "corpus"


def test_versioned_corpus_emits_reproducible_per_entity_metrics() -> None:
    cases = load_corpus(CORPUS_ROOT)

    assert {case.category for case in cases} == {"en", "evasions", "negatives", "ru"}
    assert len(cases) >= 24

    report = evaluate(DetectorEnsemble(profile=DetectorProfile.STRICT), cases)
    serialized = json.loads(report.to_json())

    assert report.case_count == len(cases)
    assert serialized["profile"] == "strict"
    for entity_type in {"EMAIL", "INN", "SNILS", "PASSPORT", "IBAN", "JWT"}:
        metric = report.per_entity[entity_type]
        assert metric.recall == 1.0
        assert metric.precision >= 0.8
