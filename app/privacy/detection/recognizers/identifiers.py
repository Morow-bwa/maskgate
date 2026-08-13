from __future__ import annotations

import re
from collections.abc import Callable

from app.privacy.models import (
    DataClass,
    DetectionContext,
    DetectorProfile,
    PrivacyDetection,
    ValidationState,
)

from ..canonical import CanonicalText
from ..validators import is_valid_iban, is_valid_inn, is_valid_snils
from .base import detection_from_span

_INN = re.compile(
    r"(?i)(?<!\w)(?:ИНН|tax\s+id)[^\d\r\n]{0,32}(?P<value>\d{10}|\d{12})(?!\d)"
)
_SNILS = re.compile(
    r"(?i)(?<!\d)(?:СНИЛС\s*[:№#]?\s*)?(?P<value>\d{3}-\d{3}-\d{3}\s?\d{2})(?!\d)"
)
_PASSPORT_CONTEXT = re.compile(
    r"(?i)\bпаспорт\s*[:№#]?\s*(?:серия\s*)?"
    r"(?P<value>\d{4}\s*[,;]?\s*(?:номер|№|#)?\s*\d{6})(?!\d)"
)
_PASSPORT_BARE = re.compile(r"(?<!\d)(?P<value>\d{4}\s+\d{6})(?!\d)")
_IBAN = re.compile(
    r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Z0-9])"
)


class StructuredIdentifierRecognizer:
    name = "structured-identifiers"
    profiles = frozenset(DetectorProfile)

    def recognize(
        self,
        text: CanonicalText,
        context: DetectionContext,
    ) -> tuple[PrivacyDetection, ...]:
        detections: list[PrivacyDetection] = []
        detections.extend(self._validated(text, context, _INN, "INN", is_valid_inn))
        detections.extend(self._validated(text, context, _SNILS, "SNILS", is_valid_snils))
        detections.extend(self._validated(text, context, _IBAN, "IBAN", is_valid_iban))

        contextual_spans: set[tuple[int, int]] = set()
        for match in _PASSPORT_CONTEXT.finditer(text.text):
            start, end = match.span("value")
            contextual_spans.add((start, end))
            detections.append(
                detection_from_span(
                    text,
                    entity_type="PASSPORT",
                    data_class=DataClass.DIRECT_PII,
                    start=start,
                    end=end,
                    confidence=0.94,
                    recognizer=self.name,
                    context=context,
                    validation_state=ValidationState.UNVALIDATED,
                    evidence=("ru-passport-label",),
                    context_score=0.25,
                )
            )
        if context.profile is DetectorProfile.STRICT:
            for match in _PASSPORT_BARE.finditer(text.text):
                span = match.span("value")
                if any(left <= span[0] and span[1] <= right for left, right in contextual_spans):
                    continue
                detections.append(
                    detection_from_span(
                        text,
                        entity_type="PASSPORT",
                        data_class=DataClass.DIRECT_PII,
                        start=span[0],
                        end=span[1],
                        confidence=0.58,
                        recognizer=self.name,
                        context=context,
                        validation_state=ValidationState.AMBIGUOUS,
                        evidence=("ru-passport-shape",),
                    )
                )
        return tuple(detections)

    def _validated(
        self,
        text: CanonicalText,
        context: DetectionContext,
        pattern: re.Pattern[str],
        entity_type: str,
        validator: Callable[[str], bool],
    ) -> list[PrivacyDetection]:
        detections: list[PrivacyDetection] = []
        for match in pattern.finditer(text.text):
            start, end = match.span("value") if "value" in match.groupdict() else match.span()
            value = text.text[start:end]
            if not validator(value):
                continue
            detections.append(
                detection_from_span(
                    text,
                    entity_type=entity_type,
                    data_class=(
                        DataClass.FINANCIAL if entity_type == "IBAN" else DataClass.DIRECT_PII
                    ),
                    start=start,
                    end=end,
                    confidence=0.995,
                    recognizer=self.name,
                    context=context,
                    validation_state=ValidationState.VALID,
                    evidence=(f"{entity_type.lower()}-checksum",),
                )
            )
        return detections
