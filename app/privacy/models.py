from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class DataClass(StrEnum):
    DIRECT_PII = "DIRECT_PII"
    QUASI_IDENTIFIER = "QUASI_IDENTIFIER"
    FINANCIAL = "FINANCIAL"
    AUTH_SECRET = "AUTH_SECRET"
    HEALTH = "HEALTH"
    LOCATION = "LOCATION"
    BUSINESS_CONFIDENTIAL = "BUSINESS_CONFIDENTIAL"
    PUBLIC_DATA = "PUBLIC_DATA"


class ValidationState(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNVALIDATED = "UNVALIDATED"
    AMBIGUOUS = "AMBIGUOUS"


class PrivacyDirection(StrEnum):
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"


class DetectorProfile(StrEnum):
    FAST = "fast"
    BALANCED = "balanced"
    STRICT = "strict"


class TokenScope(StrEnum):
    FIELD = "field"
    REQUEST = "request"
    TURN = "turn"
    CONVERSATION = "conversation"
    TENANT = "tenant"


class PrivacyAction(StrEnum):
    ALLOW = "ALLOW"
    TOKENIZE = "TOKENIZE"
    SURROGATE = "SURROGATE"
    REDACT = "REDACT"
    GENERALIZE = "GENERALIZE"
    HASH = "HASH"
    BLOCK = "BLOCK"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"


class RiskBucket(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class DetectionContext:
    locale: str = "und"
    profile: DetectorProfile = DetectorProfile.STRICT
    json_path: tuple[str | int, ...] = ()
    role: str | None = None
    direction: PrivacyDirection = PrivacyDirection.INPUT


@dataclass(frozen=True, slots=True)
class PrivacyDetection:
    entity_type: str
    data_class: DataClass
    start: int
    end: int
    confidence: float
    recognizer: str
    validation_state: ValidationState = ValidationState.UNVALIDATED
    locale: str = "und"
    evidence: tuple[str, ...] = ()
    context_score: float = 0.0

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("detection span is invalid")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("detection confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    bucket: RiskBucket
    signals: tuple[str, ...] = ()
    data_classes: frozenset[DataClass] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError("risk score must be between 0 and 100")
