from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from app.privacy.detection import DetectorEnsemble
from app.privacy.models import DetectorProfile
from evaluation.evaluate_detection import evaluate, load_corpus
from evaluation.evaluate_detection import main as evaluate_main

CORPUS_ROOT = Path(__file__).parents[2] / "evaluation" / "corpus"


def test_evaluation_gate_fails_on_mismatch_without_printing_fixture(monkeypatch, tmp_path, capsys):
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "corpus_version": "synthetic-test",
            }
        )
    )
    (tmp_path / "negative.jsonl").write_text(
        json.dumps(
            {
                "id": "intentional-mismatch",
                "text": "owner@example.com",
                "entities": [],
                "locale": "en",
                "category": "negative",
            }
        )
        + "\n"
    )
    monkeypatch.setattr(
        sys, "argv", ["evaluate", "--corpus", str(tmp_path), "--summary", "--fail-on-errors"]
    )
    with pytest.raises(SystemExit) as exc_info:
        evaluate_main()
    assert exc_info.value.code == 1
    assert "owner@example.com" not in capsys.readouterr().out


def test_versioned_corpus_emits_reproducible_per_entity_metrics() -> None:
    cases = load_corpus(CORPUS_ROOT)

    assert {"en", "evasions", "negatives", "ru", "uk", "quality"} <= {
        case.category for case in cases
    }
    assert len(cases) >= 500
    assert {
        "positive",
        "negative",
        "hard-negative",
        "multilingual",
        "obfuscated",
        "structured",
        "valid",
        "invalid",
    } <= {tag for case in cases for tag in case.tags}

    report = evaluate(DetectorEnsemble(profile=DetectorProfile.STRICT), cases)
    serialized = json.loads(report.to_json())

    assert report.case_count == len(cases)
    assert serialized["profile"] == "strict"
    assert {"en", "ru", "uk", "und"} <= set(report.per_locale)
    assert {"en", "ru", "uk", "quality"} <= set(report.per_category)
    assert "PERSON" in report.per_entity_locale["ru"]
    assert "POSTAL_ADDRESS" in report.per_entity_locale["uk"]
    for entity_type in {"EMAIL", "INN", "SNILS", "PASSPORT", "IBAN", "JWT"}:
        metric = report.per_entity[entity_type]
        assert metric.recall == 1.0
        assert metric.precision >= 0.8


def test_evaluator_keeps_weak_entity_locale_slices_visible() -> None:
    report = evaluate(
        DetectorEnsemble(profile=DetectorProfile.STRICT),
        load_corpus(CORPUS_ROOT),
    )

    for locale in {"en", "ru", "uk"}:
        for entity_type in {"PERSON", "ORG", "LOCATION", "POSTAL_ADDRESS", "DOB"}:
            assert entity_type in report.per_entity_locale[locale]
            metric = report.per_entity_locale[locale][entity_type]
            assert metric.true_positive + metric.false_negative > 0


def test_matrix_cases_are_expanded_deterministically_from_independent_fixtures() -> None:
    first = load_corpus(CORPUS_ROOT)
    second = load_corpus(CORPUS_ROOT)

    assert first == second
    assert len({case.case_id for case in first}) == len(first)
    assert len({case.text for case in first}) == len(first)
