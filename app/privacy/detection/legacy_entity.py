from __future__ import annotations

from app.masking.detector import Entity
from app.privacy.models import DetectionContext, PrivacyDetection

from .ensemble import DetectorEnsemble


class LegacyEntityDetectorAdapter:
    """Narrow Adapter from Detection Module v2 to the existing masking Seam."""

    def __init__(self, detector: DetectorEnsemble) -> None:
        self.detector = detector

    def analyze(
        self,
        text: str,
        context: DetectionContext | None = None,
    ) -> list[PrivacyDetection]:
        return self.detector.detect(text, context)

    def detect(
        self,
        text: str,
        context: DetectionContext | None = None,
    ) -> list[Entity]:
        return [
            Entity(
                type=detection.entity_type,
                text=text[detection.start : detection.end],
                start=detection.start,
                end=detection.end,
                confidence=detection.confidence,
                method=detection.recognizer,
            )
            for detection in self.analyze(text, context)
        ]
