from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator

from app.masking.detector import RegexDetector
from app.media.types import MediaContext
from app.policies.policy_engine import PolicyAction, PolicyBlocked, PolicyEngine
from app.privacy.models import DetectionContext, PrivacyAction, PrivacyDirection, TokenScope
from app.privacy.policy import PolicyContext
from app.privacy.runtime import PrivacyRuntime


@dataclass(frozen=True, slots=True)
class TextRedaction:
    text: str
    count: int
    entity_types: tuple[str, ...]


class TextRedactor:
    """Turn detector and policy decisions into irreversible, length-stable masks."""

    def __init__(
        self,
        detector: RegexDetector,
        policy: PolicyEngine,
        *,
        privacy_runtime: PrivacyRuntime | None = None,
    ) -> None:
        self.detector = detector
        self.policy = policy
        self.privacy_runtime = privacy_runtime
        self._media_context: ContextVar[MediaContext | None] = ContextVar(
            f"media_context_{id(self)}",
            default=None,
        )

    @contextmanager
    def use_media_context(self, context: MediaContext) -> Iterator[None]:
        token = self._media_context.set(context)
        try:
            yield
        finally:
            self._media_context.reset(token)

    def _entities_and_actions(self, text: str):
        context = self._media_context.get()
        if context is None or self.privacy_runtime is None:
            entities = self.detector.detect(text)
            actions = [
                self.policy.action_for_entity(entity.type, entity.text) for entity in entities
            ]
            return entities, actions

        detection_context = DetectionContext(
            profile=self.privacy_runtime.detector.profile,
            json_path=("media", "content"),
            role="media_content",
            direction=PrivacyDirection.INPUT,
        )
        detections = self.privacy_runtime.detector.detect(text, detection_context)
        risk = self.privacy_runtime.risk_engine.assess(detections)
        actions = [
            self.privacy_runtime.policy_engine.decide(
                detection,
                PolicyContext(
                    tenant=context.tenant_id,
                    application=context.application_id,
                    route=context.route,
                    direction=PrivacyDirection.INPUT,
                    provider="local-media",
                    model="local-renderer",
                    jurisdiction=context.jurisdiction,
                    purpose=context.purpose,
                    json_path=detection_context.json_path,
                    role=detection_context.role,
                    confidence=detection.confidence,
                    risk=risk,
                    recognizer=detection.recognizer,
                    token_scope=TokenScope.REQUEST,
                ),
                value=text[detection.start : detection.end],
            ).action
            for detection in detections
        ]
        return detections, actions

    def redact(self, text: str) -> TextRedaction:
        entities, actions = self._entities_and_actions(text)
        blocked = [
            self._entity_type(entity)
            for entity, action in zip(entities, actions, strict=True)
            if action in {PolicyAction.BLOCK, PrivacyAction.BLOCK, PrivacyAction.REQUIRE_REVIEW}
        ]
        if blocked:
            raise PolicyBlocked(list(dict.fromkeys(blocked)))
        entities = [
            entity
            for entity, action in zip(entities, actions, strict=True)
            if action not in {PolicyAction.ALLOW, PrivacyAction.ALLOW}
        ]
        if not entities:
            return TextRedaction(text, 0, ())

        output = text
        for entity in reversed(entities):
            output = (
                output[: entity.start]
                + ("\u2588" * (entity.end - entity.start))
                + output[entity.end :]
            )
        return TextRedaction(
            output,
            len(entities),
            tuple(dict.fromkeys(self._entity_type(entity) for entity in entities)),
        )

    def has_sensitive_text(self, text: str) -> bool:
        entities, actions = self._entities_and_actions(text)
        return any(
            action not in {PolicyAction.ALLOW, PrivacyAction.ALLOW}
            for _, action in zip(entities, actions, strict=True)
        )

    @staticmethod
    def _entity_type(entity: object) -> str:
        value = getattr(entity, "entity_type", None) or getattr(entity, "type", None)
        if not isinstance(value, str):  # pragma: no cover - detector contract invariant
            raise TypeError("detector entity type is missing")
        return value
