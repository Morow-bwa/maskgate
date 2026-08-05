from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from app.policies.policy_engine import PolicyAction, PolicyEngine, PolicyBlocked

from .detector import Entity
from .surrogate_generator import SurrogateGenerator


@dataclass(frozen=True, slots=True)
class MappingItem:
    entity_type: str
    original: str
    replacement: str
    restore: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "entity_type": self.entity_type,
            "original": self.original,
            "replacement": self.replacement,
        }


class MaskingSession:
    def __init__(self, mode: str, policy: PolicyEngine) -> None:
        if mode not in {"placeholder", "surrogate", "redact"}:
            raise ValueError(f"Unsupported masking mode: {mode}")
        self.mode = mode
        self.policy = policy
        self.surrogates = SurrogateGenerator()
        self._items: list[MappingItem] = []
        # Deduplicate by the exact value, not by (type, value). The same value
        # can be detected in different contexts or by overlapping detectors;
        # one request-scoped token keeps the model's references consistent.
        self._by_original: dict[str, MappingItem] = {}
        self._placeholder_counters: dict[str, int] = {}

    @property
    def items(self) -> list[MappingItem]:
        return list(self._items)

    def clone(self, *, policy: PolicyEngine | None = None) -> "MaskingSession":
        """Copy a vault so a blocked turn cannot partially mutate a conversation."""
        cloned = deepcopy(self)
        if policy is not None:
            cloned.policy = policy
        return cloned

    def _placeholder(self, entity_type: str) -> str:
        self._placeholder_counters[entity_type] = self._placeholder_counters.get(entity_type, 0) + 1
        return f"<{entity_type}_{self._placeholder_counters[entity_type]}>"

    def _replacement(self, entity: Entity, action: PolicyAction) -> MappingItem | None:
        if action is PolicyAction.ALLOW:
            return None
        existing = self._by_original.get(entity.text)
        if existing is not None:
            return existing

        if action is PolicyAction.REDACT:
            replacement = f"[REDACTED_{entity.type}]"
            restore = False
        elif self.mode == "placeholder":
            replacement = self._placeholder(entity.type)
            restore = True
        elif self.mode == "surrogate":
            replacement = self.surrogates.generate(entity.type)
            restore = True
        else:
            replacement = f"[REDACTED_{entity.type}]"
            restore = False

        item = MappingItem(entity.type, entity.text, replacement, restore)
        self._by_original[entity.text] = item
        self._items.append(item)
        return item

    def mask_text(self, text: str, entities: list[Entity]) -> str:
        replacements: list[tuple[int, int, str]] = []
        for entity in entities:
            action = self.policy.action_for_entity(entity.type, entity.text)
            if action is PolicyAction.BLOCK:
                raise PolicyBlocked([entity.type])
            item = self._replacement(entity, action)
            if item is not None:
                replacements.append((entity.start, entity.end, item.replacement))

        result = text
        for start, end, replacement in reversed(replacements):
            result = result[:start] + replacement + result[end:]
        return result


def mask_text(
    text: str,
    entities: list[Entity],
    mode: str,
    policy: PolicyEngine,
) -> tuple[str, list[MappingItem]]:
    session = MaskingSession(mode, policy)
    return session.mask_text(text, entities), session.items
