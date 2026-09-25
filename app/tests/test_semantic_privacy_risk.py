from __future__ import annotations

from app.privacy.models import PrivacyAction
from app.privacy.risk import (
    SemanticFeature,
    SemanticPrivacyRiskAnalyzer,
    apply_generalizations,
)


def test_compound_quasi_identifiers_produce_deterministic_local_finding() -> None:
    analyzer = SemanticPrivacyRiskAnalyzer()
    text = "A 47-year-old CFO of the only steel factory in a town of 8,000"

    assessment = analyzer.analyze(text, locale="en")

    assert len(assessment.findings) == 1
    finding = assessment.findings[0]
    assert finding.kind == "compound_quasi_identifier"
    assert finding.score == 0.95
    assert finding.features == (
        SemanticFeature.PRECISE_AGE,
        SemanticFeature.RARE_ROLE,
        SemanticFeature.SMALL_LOCATION,
        SemanticFeature.UNIQUE_EMPLOYER,
    )
    assert finding.recommended_action is PrivacyAction.REQUIRE_REVIEW


def test_one_quasi_identifier_does_not_claim_compound_semantic_risk() -> None:
    assessment = SemanticPrivacyRiskAnalyzer().analyze("A 47-year-old employee", locale="en")

    assert assessment.findings == ()
    assert assessment.generalizations[0].feature is SemanticFeature.PRECISE_AGE


def test_generalization_requires_explicit_feature_authorization() -> None:
    text = "The 43-year-old executive attended on 12 August 1983"
    assessment = SemanticPrivacyRiskAnalyzer().analyze(text, locale="en")

    unchanged = apply_generalizations(
        text, assessment.generalizations, allowed_features=frozenset()
    )
    age_only = apply_generalizations(
        text,
        assessment.generalizations,
        allowed_features=frozenset({SemanticFeature.PRECISE_AGE}),
    )
    both = apply_generalizations(
        text,
        assessment.generalizations,
        allowed_features=frozenset({SemanticFeature.PRECISE_AGE, SemanticFeature.PRECISE_DATE}),
    )

    assert unchanged == text
    assert age_only == "The person aged 40-49 executive attended on 12 August 1983"
    assert both == "The person aged 40-49 executive attended in 1983"


def test_ru_and_uk_compound_features_use_shared_bounded_analyzer() -> None:
    analyzer = SemanticPrivacyRiskAnalyzer()

    ru = analyzer.analyze(
        "47-летний финансовый директор единственного завода в городе с населением 8000",
        locale="ru",
    )
    uk = analyzer.analyze(
        "47-річний фінансовий директор єдиного заводу в місті з населенням 8000",
        locale="uk",
    )

    assert ru.findings[0].features == uk.findings[0].features
    assert SemanticFeature.PRECISE_AGE in ru.findings[0].features
    assert SemanticFeature.SMALL_LOCATION in ru.findings[0].features


def test_semantic_analysis_is_bounded_and_rejects_oversized_text() -> None:
    analyzer = SemanticPrivacyRiskAnalyzer(max_text_chars=1_000)

    try:
        analyzer.analyze("x" * 1_001)
    except ValueError as exc:
        assert str(exc) == "semantic analysis input exceeds configured limit"
    else:  # pragma: no cover - assertion helper
        raise AssertionError("oversized semantic input was accepted")
