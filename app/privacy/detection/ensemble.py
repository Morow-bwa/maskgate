from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from app.privacy.models import DetectionContext, DetectorProfile, PrivacyDetection

from .canonical import CanonicalText
from .recognizers import (
    LegacyRegexAdapter,
    NetworkRecognizer,
    Recognizer,
    SecretRecognizer,
    StructuredIdentifierRecognizer,
)

_PRIORITY = {
    "PRIVATE_KEY": 120,
    "CONNECTION_STRING": 118,
    "JWT": 116,
    "API_KEY": 114,
    "URL": 105,
    "EMAIL": 100,
    "IBAN": 98,
    "CARD_NUMBER": 96,
    "INN": 94,
    "SNILS": 94,
    "PASSPORT": 92,
    "FILE_PATH": 90,
    "PHONE": 80,
    "IP_ADDRESS": 78,
    "MONEY": 70,
    "DOMAIN": 60,
    "PERSON": 50,
}

_MIN_CONFIDENCE = {
    DetectorProfile.FAST: 0.85,
    DetectorProfile.BALANCED: 0.65,
    DetectorProfile.STRICT: 0.45,
}


class DetectorEnsemble:
    """Deep Detection Module: canonicalize, recognize, merge and resolve spans."""

    def __init__(
        self,
        recognizers: Iterable[Recognizer] | None = None,
        *,
        profile: DetectorProfile = DetectorProfile.BALANCED,
    ) -> None:
        self._recognizers = tuple(
            recognizers
            or (
                SecretRecognizer(),
                StructuredIdentifierRecognizer(),
                NetworkRecognizer(),
                LegacyRegexAdapter(),
            )
        )
        self._profile = profile

    @property
    def profile(self) -> DetectorProfile:
        return self._profile

    def detect(
        self,
        text: str,
        context: DetectionContext | None = None,
    ) -> list[PrivacyDetection]:
        active_context = context or DetectionContext(profile=self._profile)
        canonical = CanonicalText.from_text(text)
        candidates = [
            detection
            for recognizer in self._recognizers
            if active_context.profile in recognizer.profiles
            for detection in recognizer.recognize(canonical, active_context)
            if detection.confidence >= _MIN_CONFIDENCE[active_context.profile]
        ]
        return _resolve_overlaps(_merge_exact(candidates))


def _merge_exact(candidates: list[PrivacyDetection]) -> list[PrivacyDetection]:
    merged: dict[tuple[str, int, int], PrivacyDetection] = {}
    for candidate in candidates:
        key = (candidate.entity_type, candidate.start, candidate.end)
        current = merged.get(key)
        if current is None:
            merged[key] = candidate
            continue
        evidence = tuple(dict.fromkeys((*current.evidence, *candidate.evidence)))
        recognizers = tuple(dict.fromkeys((current.recognizer, candidate.recognizer)))
        merged[key] = replace(
            current if current.confidence >= candidate.confidence else candidate,
            confidence=min(1.0, max(current.confidence, candidate.confidence) + 0.02),
            recognizer="+".join(recognizers),
            evidence=evidence,
            context_score=max(current.context_score, candidate.context_score),
        )
    return list(merged.values())


def _resolve_overlaps(candidates: list[PrivacyDetection]) -> list[PrivacyDetection]:
    ordered = sorted(
        candidates,
        key=lambda item: (
            -_PRIORITY.get(item.entity_type, 0),
            -item.confidence,
            -(item.end - item.start),
            item.start,
        ),
    )
    selected: list[PrivacyDetection] = []
    for candidate in ordered:
        if any(candidate.start < item.end and item.start < candidate.end for item in selected):
            continue
        selected.append(candidate)
    return sorted(selected, key=lambda item: (item.start, item.end, item.entity_type))
