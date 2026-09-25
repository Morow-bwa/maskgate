from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from app.privacy.models import DetectionContext, DetectorProfile, PrivacyDetection

DETECTION_SEMANTICS_REVISION = "maskgate-detection-v2"

_PROFILE_STRENGTH = {
    DetectorProfile.FAST: 1,
    DetectorProfile.BALANCED: 2,
    DetectorProfile.STRICT: 3,
}


@dataclass(frozen=True, slots=True)
class DetectorCapabilityManifest:
    """Machine-checkable detection semantics for one configured detector."""

    profile: DetectorProfile
    entities: frozenset[str]
    recognizers: frozenset[str]
    minimum_confidence: float
    semantics_revision: str = DETECTION_SEMANTICS_REVISION

    def __post_init__(self) -> None:
        if not 0.0 <= self.minimum_confidence <= 1.0:
            raise ValueError("minimum confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile.value,
            "entities": sorted(self.entities),
            "recognizers": sorted(self.recognizers),
            "minimum_confidence": self.minimum_confidence,
            "semantics_revision": self.semantics_revision,
        }


@runtime_checkable
class PrivacyDetector(Protocol):
    """Provider-independent detector used at every text privacy boundary."""

    @property
    def profile(self) -> DetectorProfile: ...

    def analyze(
        self,
        text: str,
        context: DetectionContext | None = None,
    ) -> list[PrivacyDetection]: ...

    def capabilities(self) -> DetectorCapabilityManifest: ...


class DetectorCapabilityMismatch(RuntimeError):
    """A terminal privacy boundary is weaker than the ingress detector."""


def ensure_terminal_capabilities(
    ingress: PrivacyDetector,
    *,
    wire: PrivacyDetector,
    output: PrivacyDetector,
) -> None:
    ingress_manifest = ingress.capabilities()
    for boundary, detector in (("wire", wire), ("output", output)):
        terminal = detector.capabilities()
        missing = ingress_manifest.entities - terminal.entities
        if missing:
            raise DetectorCapabilityMismatch(
                f"{boundary} detector is missing ingress capabilities: "
                + ", ".join(sorted(missing))
            )
        missing_recognizers = ingress_manifest.recognizers - terminal.recognizers
        if missing_recognizers:
            raise DetectorCapabilityMismatch(
                f"{boundary} detector is missing ingress recognizers: "
                + ", ".join(sorted(missing_recognizers))
            )
        if terminal.semantics_revision != ingress_manifest.semantics_revision:
            raise DetectorCapabilityMismatch(
                f"{boundary} detector uses incompatible detection semantics"
            )
        if _PROFILE_STRENGTH[terminal.profile] < _PROFILE_STRENGTH[ingress_manifest.profile]:
            raise DetectorCapabilityMismatch(f"{boundary} detector profile is weaker than ingress")
        if terminal.minimum_confidence > ingress_manifest.minimum_confidence:
            raise DetectorCapabilityMismatch(
                f"{boundary} detector confidence threshold is weaker than ingress"
            )
