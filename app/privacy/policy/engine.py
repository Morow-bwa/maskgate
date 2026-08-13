from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from datetime import datetime, timezone
from fnmatch import fnmatchcase

from app.privacy.models import PrivacyAction, PrivacyDetection
from app.privacy.policy.models import (
    PolicyContext,
    PolicyDecision,
    PolicyDocumentV2,
    PolicyRule,
    PublicAssertionScope,
    PublicDataAssertion,
    RuleConditions,
)


def _normalize_public_value(entity_type: str, value: str) -> str:
    if entity_type.upper() == "PERSON":
        return " ".join(value.split()).casefold()
    return value.strip().casefold()


def hash_public_value(entity_type: str, value: str) -> str:
    normalized = _normalize_public_value(entity_type, value)
    material = f"{entity_type.upper()}\x00{normalized}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _matches_set(allowed: frozenset[object], actual: object) -> bool:
    return not allowed or actual in allowed


def _json_path(path: tuple[str | int, ...]) -> str:
    return ".".join(str(part) for part in path)


def _matches_conditions(
    conditions: RuleConditions,
    detection: PrivacyDetection,
    context: PolicyContext,
) -> bool:
    checks = (
        _matches_set(conditions.entity_types, detection.entity_type.upper()),
        _matches_set(conditions.data_classes, detection.data_class),
        _matches_set(conditions.tenants, context.tenant),
        _matches_set(conditions.applications, context.application),
        _matches_set(conditions.routes, context.route),
        _matches_set(conditions.directions, context.direction),
        _matches_set(conditions.providers, context.provider),
        _matches_set(conditions.models, context.model),
        _matches_set(conditions.jurisdictions, context.jurisdiction),
        _matches_set(conditions.purposes, context.purpose),
        _matches_set(conditions.roles, context.role),
        _matches_set(conditions.recognizers, context.recognizer),
        _matches_set(conditions.token_scopes, context.token_scope),
        _matches_set(conditions.risk_buckets, context.risk.bucket),
        not conditions.json_paths
        or any(
            fnmatchcase(_json_path(context.json_path), pattern) for pattern in conditions.json_paths
        ),
        conditions.min_confidence is None or context.confidence >= conditions.min_confidence,
        conditions.max_confidence is None or context.confidence <= conditions.max_confidence,
        conditions.min_risk_score is None or context.risk.score >= conditions.min_risk_score,
        conditions.max_risk_score is None or context.risk.score <= conditions.max_risk_score,
    )
    return all(checks)


def _matches_assertion_scope(scope: PublicAssertionScope, context: PolicyContext) -> bool:
    return all(
        (
            context.tenant in scope.tenants,
            context.application in scope.applications,
            context.direction in scope.directions,
            context.provider in scope.providers,
            context.purpose in scope.purposes,
            _matches_set(scope.routes, context.route),
            _matches_set(scope.models, context.model),
            _matches_set(scope.jurisdictions, context.jurisdiction),
        )
    )


class PolicyEngineV2:
    """Deterministic Policy Module with one auditable decision Interface."""

    def __init__(
        self,
        policy: PolicyDocumentV2,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._policy = policy
        self._now = now or (lambda: datetime.now(timezone.utc))

    def _public_assertion(
        self,
        detection: PrivacyDetection,
        context: PolicyContext,
        value: str,
    ) -> PublicDataAssertion | None:
        digest = hash_public_value(detection.entity_type, value)
        now = self._now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("policy clock must return a timezone-aware datetime")
        now = now.astimezone(timezone.utc)
        for assertion in self._policy.public_data_assertions:
            if assertion.expires_at <= now:
                continue
            if assertion.entity_type != detection.entity_type.upper():
                continue
            if not hmac.compare_digest(assertion.value_sha256, digest):
                continue
            if _matches_assertion_scope(assertion.scope, context):
                return assertion
        return None

    def _matching_rule(
        self, detection: PrivacyDetection, context: PolicyContext
    ) -> PolicyRule | None:
        return next(
            (
                rule
                for rule in self._policy.rules
                if _matches_conditions(rule.conditions, detection, context)
            ),
            None,
        )

    def decide(
        self,
        detection: PrivacyDetection,
        context: PolicyContext,
        *,
        value: str | None = None,
    ) -> PolicyDecision:
        # Precedence is explicit: an applicable deny/review rule, an active
        # scoped public assertion, any remaining rule, then the fail-closed
        # default. Public status can relax routine tokenization, but it can
        # never override a contextual prohibition.
        rule = self._matching_rule(detection, context)
        if rule is not None and rule.action in {
            PrivacyAction.BLOCK,
            PrivacyAction.REQUIRE_REVIEW,
        }:
            return PolicyDecision(
                action=rule.action,
                reason=rule.reason,
                policy_version=self._policy.version,
                obligations=rule.obligations,
                rule_id=rule.rule_id,
            )
        if value is not None:
            assertion = self._public_assertion(detection, context, value)
            if assertion is not None:
                return PolicyDecision(
                    action=assertion.action,
                    reason=assertion.reason,
                    policy_version=self._policy.version,
                    obligations=assertion.obligations,
                    assertion_id=assertion.assertion_id,
                )

        if rule is not None:
            return PolicyDecision(
                action=rule.action,
                reason=rule.reason,
                policy_version=self._policy.version,
                obligations=rule.obligations,
                rule_id=rule.rule_id,
            )
        return PolicyDecision(
            action=self._policy.default_action,
            reason=self._policy.default_reason,
            policy_version=self._policy.version,
            obligations=self._policy.default_obligations,
        )
