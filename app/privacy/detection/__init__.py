"""Local, provider-independent privacy detection primitives."""

from .canonical import CanonicalizationError, CanonicalText
from .contract import (
    DetectorCapabilityManifest,
    DetectorCapabilityMismatch,
    PrivacyDetector,
    ensure_terminal_capabilities,
)
from .ensemble import DetectorEnsemble
from .legacy_entity import LegacyEntityDetectorAdapter
from .recognizers import Recognizer

__all__ = [
    "CanonicalText",
    "CanonicalizationError",
    "DetectorCapabilityManifest",
    "DetectorCapabilityMismatch",
    "DetectorEnsemble",
    "LegacyEntityDetectorAdapter",
    "PrivacyDetector",
    "Recognizer",
    "ensure_terminal_capabilities",
]
