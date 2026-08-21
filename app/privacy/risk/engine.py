from __future__ import annotations

from collections.abc import Iterable

from app.privacy.models import (
    DataClass,
    PrivacyDetection,
    RiskAssessment,
    RiskBucket,
    ValidationState,
)

_BASE_WEIGHT: dict[DataClass, int] = {
    DataClass.PUBLIC_DATA: 5,
    DataClass.QUASI_IDENTIFIER: 30,
    DataClass.LOCATION: 35,
    DataClass.BUSINESS_CONFIDENTIAL: 45,
    DataClass.DIRECT_PII: 55,
    DataClass.FINANCIAL: 70,
    DataClass.HEALTH: 75,
    DataClass.AUTH_SECRET: 90,
}


def _bucket(score: int) -> RiskBucket:
    if score >= 75:
        return RiskBucket.CRITICAL
    if score >= 50:
        return RiskBucket.HIGH
    if score >= 25:
        return RiskBucket.MEDIUM
    return RiskBucket.LOW


class PrivacyRiskEngine:
    """Pure deterministic Implementation of the privacy-risk Interface.

    The Module consumes only classified detection metadata. It never accepts or
    returns raw sensitive values, keeping the risk/policy Seam narrow and safe.
    """

    def assess(self, detections: Iterable[PrivacyDetection]) -> RiskAssessment:
        ordered = tuple(
            sorted(
                detections,
                key=lambda item: (
                    item.data_class.value,
                    item.entity_type,
                    item.start,
                    item.end,
                    item.recognizer,
                ),
            )
        )
        if not ordered:
            return RiskAssessment(
                score=0,
                bucket=RiskBucket.LOW,
                signals=("no_sensitive_signals",),
            )

        classes = frozenset(item.data_class for item in ordered)
        effective = tuple(
            item for item in ordered if item.validation_state is not ValidationState.INVALID
        )
        effective_classes = frozenset(item.data_class for item in effective)
        signals = {f"class:{data_class.value}" for data_class in classes}
        weighted_scores: list[int] = []

        for detection in ordered:
            base = _BASE_WEIGHT[detection.data_class]
            confidence_factor = max(0.25, detection.confidence)
            score = round(base * confidence_factor)

            if detection.validation_state is ValidationState.VALID:
                score += 5
            elif detection.validation_state is ValidationState.INVALID:
                score = min(score, 15)
                signals.add("validation:invalid")
            elif detection.validation_state is ValidationState.AMBIGUOUS:
                score += 5
                signals.add("validation:ambiguous")
            else:
                signals.add("validation:unvalidated")

            weighted_scores.append(score)

        total = max(weighted_scores)

        quasi_count = len(
            {
                item.entity_type
                for item in effective
                if item.data_class is DataClass.QUASI_IDENTIFIER
            }
        )
        if quasi_count >= 3:
            total += 25
            signals.add(f"combination:quasi_identifiers:{quasi_count}")
        elif quasi_count == 2:
            total += 12
            signals.add("combination:quasi_identifiers:2")

        if (
            DataClass.DIRECT_PII in effective_classes
            and DataClass.QUASI_IDENTIFIER in effective_classes
        ):
            total += 12
            signals.add("combination:direct_pii_plus_quasi")
        if (
            DataClass.LOCATION in effective_classes
            and DataClass.QUASI_IDENTIFIER in effective_classes
        ):
            total += 10
            signals.add("combination:location_plus_quasi")
        if DataClass.FINANCIAL in effective_classes and DataClass.DIRECT_PII in effective_classes:
            total += 10
            signals.add("combination:financial_plus_direct_pii")
        if len(ordered) > 1:
            total += min(10, (len(ordered) - 1) * 2)
            signals.add("combination:multiple_detections")

        total = min(100, total)
        return RiskAssessment(
            score=total,
            bucket=_bucket(total),
            signals=tuple(sorted(signals)),
            data_classes=classes,
        )
