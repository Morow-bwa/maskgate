from __future__ import annotations

import re
from datetime import date

from app.privacy.models import (
    DataClass,
    DetectionContext,
    DetectorProfile,
    PrivacyDetection,
    ValidationState,
)

from ..canonical import CanonicalText
from ..locales import LocalePack, packs_for_locale
from .base import detection_from_span

_TITLE_WORD = r"[A-ZА-ЯЁІЇЄҐ][a-zа-яёіїєґ]+(?:[’'\-][A-ZА-ЯЁІЇЄҐ]?[a-zа-яёіїєґ]+)?"
_NAME = rf"{_TITLE_WORD}(?:\s+{_TITLE_WORD}){{1,2}}"
_ORG_NAME = rf"{_TITLE_WORD}(?:\s+{_TITLE_WORD}){{0,3}}"
_DATE_NUMERIC = r"\d{1,4}[.\-/]\d{1,2}[.\-/]\d{1,4}"


def _alternation(values: tuple[str, ...] | frozenset[str]) -> str:
    return "|".join(sorted((re.escape(item) for item in values), key=len, reverse=True))


class LocalizedContextRecognizer:
    """Deterministic RU/UK/EN context and dictionary-assisted recognizer.

    Locale packs contain vocabulary only. Recognition, validation, confidence,
    and span provenance stay shared so adding a locale does not copy code.
    """

    name = "localized-context"
    profiles = frozenset(DetectorProfile)
    capabilities = frozenset({"PERSON", "ORG", "LOCATION", "POSTAL_ADDRESS", "DOB"})

    def recognize(
        self,
        text: CanonicalText,
        context: DetectionContext,
    ) -> tuple[PrivacyDetection, ...]:
        detections: dict[tuple[str, int, int], PrivacyDetection] = {}
        for pack in packs_for_locale(context.locale):
            for detection in self._recognize_pack(text, context, pack):
                key = (detection.entity_type, detection.start, detection.end)
                current = detections.get(key)
                if current is None or detection.confidence > current.confidence:
                    detections[key] = detection
        return tuple(detections.values())

    def _recognize_pack(
        self,
        text: CanonicalText,
        context: DetectionContext,
        pack: LocalePack,
    ) -> tuple[PrivacyDetection, ...]:
        return (
            *self._people(text, context, pack),
            *self._organizations(text, context, pack),
            *self._locations(text, context, pack),
            *self._addresses(text, context, pack),
            *self._dates_of_birth(text, context, pack),
        )

    def _people(
        self,
        text: CanonicalText,
        context: DetectionContext,
        pack: LocalePack,
    ) -> tuple[PrivacyDetection, ...]:
        spans: dict[tuple[int, int], tuple[float, tuple[str, ...], float]] = {}
        labels = _alternation(pack.person_labels)
        labeled = re.compile(rf"(?i:(?:{labels}))\s*(?:[:—-]\s*)?(?P<value>{_NAME})")
        for match in labeled.finditer(text.text):
            spans[match.span("value")] = (0.95, (f"{pack.language}-person-label",), 0.30)

        given_names = _alternation(pack.given_names)
        dictionary_assisted = re.compile(
            rf"(?<![\w-])(?P<value>(?i:{given_names})\s+{_TITLE_WORD}(?:\s+{_TITLE_WORD})?)(?![\w-])"
        )
        for match in dictionary_assisted.finditer(text.text):
            start, end = match.span("value")
            value = text.text[start:end]
            first, *rest = value.split()
            if first != first.title() or not all(part == part.title() for part in rest):
                continue
            spans.setdefault(
                (start, end),
                (0.86, (f"{pack.language}-given-name-lexicon",), 0.12),
            )

        return tuple(
            detection_from_span(
                text,
                entity_type="PERSON",
                data_class=DataClass.DIRECT_PII,
                start=start,
                end=end,
                confidence=confidence,
                recognizer=self.name,
                context=context,
                validation_state=ValidationState.UNVALIDATED,
                evidence=evidence,
                context_score=context_score,
            )
            for (start, end), (confidence, evidence, context_score) in spans.items()
        )

    def _organizations(
        self,
        text: CanonicalText,
        context: DetectionContext,
        pack: LocalePack,
    ) -> tuple[PrivacyDetection, ...]:
        spans: set[tuple[int, int]] = set()
        if pack.organization_prefixes:
            markers = _alternation(pack.organization_prefixes)
            pattern = re.compile(
                rf"(?<!\w)(?P<value>(?i:{markers})\s+[«\"“]?{_ORG_NAME}[»\"”]?)(?!\w)"
            )
            spans.update(match.span("value") for match in pattern.finditer(text.text))
        if pack.organization_suffixes:
            markers = _alternation(pack.organization_suffixes)
            pattern = re.compile(
                rf"(?<!\w)(?!(?i:Employer)\b)"
                rf"(?P<value>{_ORG_NAME}\s+(?i:{markers}))(?!\w)"
            )
            spans.update(match.span("value") for match in pattern.finditer(text.text))
        return tuple(
            detection_from_span(
                text,
                entity_type="ORG",
                data_class=DataClass.BUSINESS_CONFIDENTIAL,
                start=start,
                end=end,
                confidence=0.97,
                recognizer=self.name,
                context=context,
                validation_state=ValidationState.UNVALIDATED,
                evidence=(f"{pack.language}-legal-form",),
                context_score=0.25,
            )
            for start, end in spans
        )

    def _locations(
        self,
        text: CanonicalText,
        context: DetectionContext,
        pack: LocalePack,
    ) -> tuple[PrivacyDetection, ...]:
        if not pack.locations:
            return ()
        locations = _alternation(pack.locations)
        pattern = re.compile(rf"(?<![\w-])(?P<value>(?i:{locations}))(?![\w-])")
        return tuple(
            detection_from_span(
                text,
                entity_type="LOCATION",
                data_class=DataClass.LOCATION,
                start=match.start("value"),
                end=match.end("value"),
                confidence=0.93,
                recognizer=self.name,
                context=context,
                validation_state=ValidationState.UNVALIDATED,
                evidence=(f"{pack.language}-location-lexicon",),
            )
            for match in pattern.finditer(text.text)
        )

    def _addresses(
        self,
        text: CanonicalText,
        context: DetectionContext,
        pack: LocalePack,
    ) -> tuple[PrivacyDetection, ...]:
        if pack.language == "en":
            street_markers = _alternation(pack.street_markers)
            unit_markers = _alternation(pack.unit_markers)
            pattern = re.compile(
                rf"(?<!\w)(?P<value>\d{{1,5}}[A-Za-z]?\s+{_ORG_NAME}\s+"
                rf"(?i:{street_markers})(?:,?\s+(?i:{unit_markers})\.?\s+[A-Za-z0-9-]+)?)(?!\w)"
            )
        else:
            street_markers = _alternation(pack.street_markers)
            house_markers = _alternation(pack.house_markers)
            unit_markers = _alternation(pack.unit_markers)
            pattern = re.compile(
                rf"(?<!\w)(?P<value>(?i:{street_markers})\.?\s+{_ORG_NAME},?\s+"
                rf"(?i:{house_markers})\.?\s*\d+[A-Za-zА-Яа-яІіЇїЄєҐґ]?(?:,?\s+"
                rf"(?i:{unit_markers})\.?\s*\d+[A-Za-zА-Яа-яІіЇїЄєҐґ]?)?)(?!\w)"
            )
        detections: list[PrivacyDetection] = []
        for match in pattern.finditer(text.text):
            start, end = match.span("value")
            if end < len(text.text) and text.text[end] == ".":
                marker = text.text[start:end].rsplit(maxsplit=1)[-1].casefold()
                if marker in {"st", "rd", "ave", "ln", "dr", "blvd"}:
                    end += 1
            detections.append(
                detection_from_span(
                    text,
                    entity_type="POSTAL_ADDRESS",
                    data_class=DataClass.LOCATION,
                    start=start,
                    end=end,
                    confidence=0.96,
                    recognizer=self.name,
                    context=context,
                    validation_state=ValidationState.UNVALIDATED,
                    evidence=(f"{pack.language}-postal-shape",),
                    context_score=0.28,
                )
            )
        return tuple(detections)

    def _dates_of_birth(
        self,
        text: CanonicalText,
        context: DetectionContext,
        pack: LocalePack,
    ) -> tuple[PrivacyDetection, ...]:
        labels = _alternation(pack.dob_labels)
        months = _alternation(tuple(month for month, _ in pack.months))
        word_date = rf"\d{{1,2}}\s+(?i:{months})\s+\d{{4}}"
        pattern = re.compile(
            rf"(?i:(?:{labels}))\s*(?::|—|-|on)?\s*(?P<value>{_DATE_NUMERIC}|{word_date})"
        )
        detections: list[PrivacyDetection] = []
        for match in pattern.finditer(text.text):
            value = match.group("value")
            if not _is_valid_dob(value, pack):
                continue
            detections.append(
                detection_from_span(
                    text,
                    entity_type="DOB",
                    data_class=DataClass.DIRECT_PII,
                    start=match.start("value"),
                    end=match.end("value"),
                    confidence=0.98,
                    recognizer=self.name,
                    context=context,
                    validation_state=ValidationState.VALID,
                    evidence=(f"{pack.language}-dob-context", "calendar-valid"),
                    context_score=0.35,
                )
            )
        return tuple(detections)


def _is_valid_dob(value: str, pack: LocalePack) -> bool:
    normalized = value.casefold()
    try:
        month_lookup = dict(pack.months)
        month_name = next((name for name in month_lookup if name in normalized), None)
        if month_name is not None:
            day_text, _, year_text = normalized.split()
            parsed = date(int(year_text), month_lookup[month_name], int(day_text))
        else:
            parts = re.split(r"[.\-/]", normalized)
            if len(parts[0]) == 4:
                year_text, month_text, day_text = parts
            elif pack.numeric_date_order == "MDY":
                month_text, day_text, year_text = parts
            else:
                day_text, month_text, year_text = parts
            parsed = date(int(year_text), int(month_text), int(day_text))
    except (TypeError, ValueError):
        return False
    return date(1900, 1, 1) <= parsed <= date.today()
