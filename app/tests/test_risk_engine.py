from __future__ import annotations

from app.privacy.models import (
    DataClass,
    PrivacyDetection,
    RiskBucket,
    ValidationState,
)
from app.privacy.risk import PrivacyRiskEngine


def _detection(
    entity_type: str,
    data_class: DataClass,
    *,
    confidence: float = 0.9,
    validation_state: ValidationState = ValidationState.VALID,
) -> PrivacyDetection:
    return PrivacyDetection(
        entity_type=entity_type,
        data_class=data_class,
        start=0,
        end=5,
        confidence=confidence,
        recognizer="test-recognizer",
        validation_state=validation_state,
    )


def test_empty_detection_set_has_zero_risk() -> None:
    assessment = PrivacyRiskEngine().assess([])

    assert assessment.score == 0
    assert assessment.bucket is RiskBucket.LOW
    assert assessment.signals == ("no_sensitive_signals",)
    assert assessment.data_classes == frozenset()


def test_auth_secret_is_critical_and_deterministic() -> None:
    detections = [
        _detection("EMAIL", DataClass.DIRECT_PII),
        _detection("API_KEY", DataClass.AUTH_SECRET, confidence=1.0),
    ]
    engine = PrivacyRiskEngine()

    forward = engine.assess(detections)
    reverse = engine.assess(reversed(detections))

    assert forward == reverse
    assert forward.bucket is RiskBucket.CRITICAL
    assert forward.score >= 90
    assert "class:AUTH_SECRET" in forward.signals


def test_quasi_identifiers_gain_combination_risk() -> None:
    engine = PrivacyRiskEngine()
    single = engine.assess([_detection("AGE", DataClass.QUASI_IDENTIFIER)])
    combined = engine.assess(
        [
            _detection("AGE", DataClass.QUASI_IDENTIFIER),
            _detection("POSTCODE", DataClass.QUASI_IDENTIFIER),
            _detection("EMPLOYER", DataClass.QUASI_IDENTIFIER),
        ]
    )

    assert combined.score > single.score
    assert combined.bucket in {RiskBucket.HIGH, RiskBucket.CRITICAL}
    assert "combination:quasi_identifiers:3" in combined.signals


def test_repeated_same_quasi_identifier_is_not_a_combination() -> None:
    assessment = PrivacyRiskEngine().assess(
        [
            _detection("AGE", DataClass.QUASI_IDENTIFIER),
            _detection("AGE", DataClass.QUASI_IDENTIFIER),
            _detection("AGE", DataClass.QUASI_IDENTIFIER),
        ]
    )

    assert not any(
        signal.startswith("combination:quasi_identifiers") for signal in assessment.signals
    )


def test_quasi_identifier_combined_with_direct_pii_is_high_risk() -> None:
    assessment = PrivacyRiskEngine().assess(
        [
            _detection("AGE", DataClass.QUASI_IDENTIFIER),
            _detection("EMAIL", DataClass.DIRECT_PII),
        ]
    )

    assert assessment.bucket in {RiskBucket.HIGH, RiskBucket.CRITICAL}
    assert "combination:direct_pii_plus_quasi" in assessment.signals


def test_invalid_candidate_does_not_receive_valid_identifier_weight() -> None:
    engine = PrivacyRiskEngine()
    valid = engine.assess([_detection("CARD_NUMBER", DataClass.FINANCIAL, confidence=1.0)])
    invalid = engine.assess(
        [
            _detection(
                "CARD_NUMBER",
                DataClass.FINANCIAL,
                confidence=1.0,
                validation_state=ValidationState.INVALID,
            )
        ]
    )

    assert invalid.score < valid.score
    assert "validation:invalid" in invalid.signals


def test_assessment_contains_no_raw_detection_value() -> None:
    assessment = PrivacyRiskEngine().assess([_detection("EMAIL", DataClass.DIRECT_PII)])

    serialized = repr(assessment)
    assert "test-recognizer" not in serialized
    assert "EMAIL" not in serialized
