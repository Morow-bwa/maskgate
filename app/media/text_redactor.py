from __future__ import annotations

from dataclasses import dataclass

from app.masking.detector import RegexDetector
from app.policies.policy_engine import PolicyAction, PolicyBlocked, PolicyEngine


@dataclass(frozen=True, slots=True)
class TextRedaction:
    text: str
    count: int
    entity_types: tuple[str, ...]


class TextRedactor:
    """Turn detector and policy decisions into irreversible, length-stable masks."""

    def __init__(self, detector: RegexDetector, policy: PolicyEngine) -> None:
        self.detector = detector
        self.policy = policy

    def redact(self, text: str) -> TextRedaction:
        entities = self.detector.detect(text)
        actions = [self.policy.action_for_entity(entity.type, entity.text) for entity in entities]
        blocked = [
            entity.type
            for entity, action in zip(entities, actions, strict=True)
            if action is PolicyAction.BLOCK
        ]
        if blocked:
            raise PolicyBlocked(list(dict.fromkeys(blocked)))
        entities = [
            entity
            for entity, action in zip(entities, actions, strict=True)
            if action is not PolicyAction.ALLOW
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
            tuple(dict.fromkeys(entity.type for entity in entities)),
        )

    def has_sensitive_text(self, text: str) -> bool:
        return any(
            self.policy.action_for_entity(entity.type, entity.text) is not PolicyAction.ALLOW
            for entity in self.detector.detect(text)
        )
