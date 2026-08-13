from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.privacy.models import (
    DataClass,
    PrivacyAction,
    PrivacyDirection,
    RiskAssessment,
    RiskBucket,
    TokenScope,
)


@dataclass(frozen=True, slots=True)
class PolicyContext:
    tenant: str
    application: str
    route: str
    direction: PrivacyDirection
    provider: str
    model: str
    jurisdiction: str
    purpose: str
    json_path: tuple[str | int, ...]
    role: str | None
    confidence: float
    risk: RiskAssessment
    recognizer: str
    token_scope: TokenScope

    def __post_init__(self) -> None:
        required = {
            "tenant": self.tenant,
            "application": self.application,
            "route": self.route,
            "provider": self.provider,
            "model": self.model,
            "jurisdiction": self.jurisdiction,
            "purpose": self.purpose,
            "recognizer": self.recognizer,
        }
        missing = [name for name, value in required.items() if not value.strip()]
        if missing:
            raise ValueError(f"policy context requires non-empty {', '.join(missing)}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("policy context confidence must be between 0 and 1")
        if not isinstance(self.direction, PrivacyDirection):
            raise ValueError("policy context direction must be PrivacyDirection")
        if not isinstance(self.token_scope, TokenScope):
            raise ValueError("policy context token_scope must be TokenScope")
        if not isinstance(self.risk, RiskAssessment):
            raise ValueError("policy context risk must be RiskAssessment")
        if not isinstance(self.json_path, tuple) or any(
            not isinstance(part, (str, int)) for part in self.json_path
        ):
            raise ValueError("policy context json_path must be a tuple of strings and integers")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: PrivacyAction
    reason: str
    policy_version: str
    obligations: tuple[str, ...]
    rule_id: str | None = None
    assertion_id: str | None = None


@dataclass(frozen=True, slots=True)
class RuleConditions:
    entity_types: frozenset[str] = frozenset()
    data_classes: frozenset[DataClass] = frozenset()
    tenants: frozenset[str] = frozenset()
    applications: frozenset[str] = frozenset()
    routes: frozenset[str] = frozenset()
    directions: frozenset[PrivacyDirection] = frozenset()
    providers: frozenset[str] = frozenset()
    models: frozenset[str] = frozenset()
    jurisdictions: frozenset[str] = frozenset()
    purposes: frozenset[str] = frozenset()
    json_paths: tuple[str, ...] = ()
    roles: frozenset[str] = frozenset()
    recognizers: frozenset[str] = frozenset()
    token_scopes: frozenset[TokenScope] = frozenset()
    risk_buckets: frozenset[RiskBucket] = frozenset()
    min_confidence: float | None = None
    max_confidence: float | None = None
    min_risk_score: int | None = None
    max_risk_score: int | None = None


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    priority: int
    action: PrivacyAction
    reason: str
    obligations: tuple[str, ...]
    conditions: RuleConditions


@dataclass(frozen=True, slots=True)
class PublicAssertionScope:
    tenants: frozenset[str]
    applications: frozenset[str]
    directions: frozenset[PrivacyDirection]
    providers: frozenset[str]
    purposes: frozenset[str]
    routes: frozenset[str] = frozenset()
    models: frozenset[str] = frozenset()
    jurisdictions: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class PublicDataAssertion:
    assertion_id: str
    entity_type: str
    value_sha256: str
    action: PrivacyAction
    reason: str
    obligations: tuple[str, ...]
    scope: PublicAssertionScope
    expires_at: datetime
    provenance: str


@dataclass(frozen=True, slots=True)
class PolicyDocumentV2:
    version: str
    default_action: PrivacyAction
    default_reason: str
    default_obligations: tuple[str, ...]
    rules: tuple[PolicyRule, ...]
    public_data_assertions: tuple[PublicDataAssertion, ...]


class PolicySchemaError(ValueError):
    """Raised when strict Policy Module validation fails."""


YamlMapping = dict[str, Any]
