from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.privacy.models import (
    DataClass,
    DetectionContext,
    DetectorProfile,
    PrivacyDetection,
    ValidationState,
)

from ..canonical import CanonicalText


@runtime_checkable
class Recognizer(Protocol):
    """Interface implemented by every local detection Adapter."""

    name: str
    profiles: frozenset[DetectorProfile]
    capabilities: frozenset[str]

    def recognize(
        self,
        text: CanonicalText,
        context: DetectionContext,
    ) -> tuple[PrivacyDetection, ...]: ...


def detection_from_span(
    text: CanonicalText,
    *,
    entity_type: str,
    data_class: DataClass,
    start: int,
    end: int,
    confidence: float,
    recognizer: str,
    context: DetectionContext,
    validation_state: ValidationState = ValidationState.UNVALIDATED,
    evidence: tuple[str, ...] = (),
    context_score: float = 0.0,
) -> PrivacyDetection:
    original_start, original_end = text.original_span(start, end)
    return PrivacyDetection(
        entity_type=entity_type,
        data_class=data_class,
        start=original_start,
        end=original_end,
        confidence=confidence,
        recognizer=recognizer,
        validation_state=validation_state,
        locale=context.locale,
        evidence=evidence,
        context_score=context_score,
    )
