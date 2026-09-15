from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace

from app.privacy.models import PrivacyDirection


def _value_fingerprint(entity_type: str, value: str) -> bytes:
    material = f"{entity_type.upper()}\x00{value}".encode("utf-8")
    return hashlib.sha256(material).digest()


@dataclass(frozen=True, slots=True)
class ApprovalContext:
    """Trusted operation scope used to validate an in-memory policy grant."""

    principal_id: str
    application_id: str
    route: str
    provider: str
    direction: PrivacyDirection
    purpose: str
    policy_revision: str
    now_epoch: float


@dataclass(frozen=True, slots=True)
class ScopedApproval:
    """Request-local evidence for one detected value at one serialized path."""

    value_fingerprint: bytes
    entity_type: str
    principal_id: str
    application_id: str
    route: str
    provider: str
    direction: PrivacyDirection
    purpose: str
    source_path: tuple[str | int, ...]
    wire_path: tuple[str | int, ...]
    policy_revision: str
    expires_at_epoch: float
    decision_id: str

    def bind_to_wire(
        self,
        *,
        provider: str,
        wire_path: tuple[str | int, ...],
    ) -> ScopedApproval:
        return replace(self, provider=provider, wire_path=wire_path)

    def scope_matches(self, context: ApprovalContext) -> bool:
        return (
            context.now_epoch < self.expires_at_epoch
            and self.principal_id == context.principal_id
            and self.application_id == context.application_id
            and self.route == context.route
            and self.provider == context.provider
            and self.direction is context.direction
            and self.purpose == context.purpose
            and self.policy_revision == context.policy_revision
        )

    def matches_value(self, value: str, entity_type: str) -> bool:
        return entity_type.upper() == self.entity_type and hmac.compare_digest(
            self.value_fingerprint,
            _value_fingerprint(entity_type, value),
        )

    @classmethod
    def issue(
        cls,
        *,
        value: str,
        entity_type: str,
        principal_id: str,
        application_id: str,
        route: str,
        provider: str,
        direction: PrivacyDirection,
        purpose: str,
        source_path: tuple[str | int, ...],
        wire_path: tuple[str | int, ...],
        policy_revision: str,
        expires_at_epoch: float,
        decision_id: str,
    ) -> ScopedApproval:
        return cls(
            value_fingerprint=_value_fingerprint(entity_type, value),
            entity_type=entity_type.upper(),
            principal_id=principal_id,
            application_id=application_id,
            route=route,
            provider=provider,
            direction=direction,
            purpose=purpose,
            source_path=source_path,
            wire_path=wire_path,
            policy_revision=policy_revision,
            expires_at_epoch=expires_at_epoch,
            decision_id=decision_id,
        )

    def approves(
        self,
        *,
        value: str,
        entity_type: str,
        path: tuple[str | int, ...],
        context: ApprovalContext,
    ) -> bool:
        return (
            self.scope_matches(context)
            and path == self.wire_path
            and self.matches_value(value, entity_type)
        )
