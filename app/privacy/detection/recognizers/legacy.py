from __future__ import annotations

import re

from app.masking.regex_patterns import PATTERNS, PatternSpec
from app.privacy.models import (
    DataClass,
    DetectionContext,
    DetectorProfile,
    PrivacyDetection,
    ValidationState,
)

from ..canonical import CanonicalText
from ..validators import is_valid_inn, is_valid_luhn
from .base import detection_from_span

_ALL_PROFILES = frozenset(DetectorProfile)

_DATA_CLASSES: dict[str, DataClass] = {
    "API_KEY": DataClass.AUTH_SECRET,
    "BANK": DataClass.FINANCIAL,
    "CARD_NUMBER": DataClass.FINANCIAL,
    "DOMAIN": DataClass.QUASI_IDENTIFIER,
    "EMAIL": DataClass.DIRECT_PII,
    "FILE_PATH": DataClass.BUSINESS_CONFIDENTIAL,
    "INN": DataClass.DIRECT_PII,
    "IP_ADDRESS": DataClass.QUASI_IDENTIFIER,
    "LOCATION": DataClass.LOCATION,
    "MONEY": DataClass.FINANCIAL,
    "ORG": DataClass.BUSINESS_CONFIDENTIAL,
    "PASSPORT": DataClass.DIRECT_PII,
    "PERSON": DataClass.DIRECT_PII,
    "PHONE": DataClass.DIRECT_PII,
    "SNILS": DataClass.DIRECT_PII,
    "URL": DataClass.QUASI_IDENTIFIER,
}

_VALID_BY_PATTERN = frozenset({"EMAIL", "IP_ADDRESS", "URL"})


def _touches_identifier(text: str, start: int, end: int) -> bool:
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    return bool(
        (before and (before.isalnum() or before in "_-"))
        or (after and (after.isalnum() or after in "_-"))
    )


class LegacyRegexAdapter:
    """Adapter that preserves useful legacy patterns behind the Recognizer Seam."""

    name = "legacy-regex"
    profiles = _ALL_PROFILES

    def __init__(self, patterns: tuple[PatternSpec, ...] = PATTERNS) -> None:
        self._patterns = patterns

    def recognize(
        self,
        text: CanonicalText,
        context: DetectionContext,
    ) -> tuple[PrivacyDetection, ...]:
        detections: list[PrivacyDetection] = []
        for spec in self._patterns:
            entity_type = spec.entity_type.value
            for match in spec.pattern.finditer(text.text):
                candidate = self._from_match(text, context, spec, match, entity_type)
                if candidate is not None:
                    detections.append(candidate)
        return tuple(detections)

    def _from_match(
        self,
        text: CanonicalText,
        context: DetectionContext,
        spec: PatternSpec,
        match: re.Match[str],
        entity_type: str,
    ) -> PrivacyDetection | None:
        start, end = match.span(spec.capture_group) if spec.capture_group else match.span()
        while end > start and text.text[end - 1] in ".,;:!?)]}>":
            end -= 1
        if end <= start:
            return None

        validation = ValidationState.UNVALIDATED
        confidence = 0.82
        value = text.text[start:end]
        if entity_type in _VALID_BY_PATTERN:
            validation = ValidationState.VALID
            confidence = 0.97
        elif entity_type == "CARD_NUMBER":
            if _touches_identifier(text.text, start, end):
                return None
            validation = ValidationState.VALID if is_valid_luhn(value) else ValidationState.INVALID
            confidence = 0.99 if validation is ValidationState.VALID else 0.52
        elif entity_type == "INN":
            validation = ValidationState.VALID if is_valid_inn(value) else ValidationState.INVALID
            confidence = 0.99 if validation is ValidationState.VALID else 0.58

        if validation is ValidationState.INVALID and context.profile is not DetectorProfile.STRICT:
            return None
        return detection_from_span(
            text,
            entity_type=entity_type,
            data_class=_DATA_CLASSES[entity_type],
            start=start,
            end=end,
            confidence=confidence,
            recognizer=self.name,
            context=context,
            validation_state=validation,
            evidence=("legacy-pattern",),
        )
