from __future__ import annotations

import base64
import re
import secrets
from copy import deepcopy
from typing import Any, Iterable

from app.policies.policy_engine import PolicyAction, PolicyBlocked, PolicyEngine
from app.privacy.models import PrivacyAction
from app.privacy.vault import (
    InMemoryVault,
    MappingItem,
    VaultBudget,
    VaultCapacityExceeded,
)

from .detector import Entity
from .surrogate_generator import SurrogateGenerator

__all__ = ["MappingItem", "MaskingSession", "ReservedTokenInjection", "VaultCapacityExceeded"]

RESERVED_TOKEN_PATTERN = re.compile(
    r"(?:<MG:[A-Z2-7]{26}>|<MG_[A-Za-z0-9_-]{4,64}_[A-Z][A-Z0-9_]*_\d+>)"
)


class ReservedTokenInjection(PolicyBlocked):
    def __init__(self) -> None:
        self.entity_types = ["RESERVED_TOKEN"]
        Exception.__init__(self, "Input contains reserved MaskGate token syntax")


class MaskingSession:
    def __init__(
        self,
        mode: str,
        policy: PolicyEngine,
        *,
        token_namespace: str | None = None,
        max_mappings: int = 5_000,
        max_sensitive_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        if mode not in {"placeholder", "semantic_placeholder", "surrogate", "redact"}:
            raise ValueError(f"Unsupported masking mode: {mode}")
        self.mode = mode
        self.policy = policy
        namespace = token_namespace or secrets.token_hex(6)
        if not re.fullmatch(r"[A-Za-z0-9_-]{4,64}", namespace):
            raise ValueError("Invalid placeholder token namespace")
        self.token_namespace = namespace
        self.surrogates = SurrogateGenerator()
        self.vault = InMemoryVault(VaultBudget(max_mappings, max_sensitive_bytes))
        self._placeholder_counters: dict[str, int] = {}

    @property
    def items(self) -> list[MappingItem]:
        return list(self.vault.items)

    def clone(self, *, policy: PolicyEngine | None = None) -> "MaskingSession":
        """Copy a vault so a blocked turn cannot partially mutate a conversation."""
        cloned = deepcopy(self)
        if policy is not None:
            cloned.policy = policy
        return cloned

    def prune_to_references(self, values: Iterable[Any]) -> None:
        """Drop originals whose reversible replacements are no longer referenced."""

        self.vault.prune_to_references(values)

    def _placeholder(self, entity_type: str) -> str:
        if self.mode == "placeholder":
            while True:
                opaque_id = base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
                token = f"<MG:{opaque_id}>"
                if not self.vault.contains_replacement(token) and not self.vault.contains_original(
                    token
                ):
                    return token
        self._placeholder_counters[entity_type] = self._placeholder_counters.get(entity_type, 0) + 1
        return (
            f"<MG_{self.token_namespace}_{entity_type}_{self._placeholder_counters[entity_type]}>"
        )

    def _replacement(self, entity: Entity, action: PolicyAction) -> MappingItem | None:
        if action is PolicyAction.ALLOW:
            return None
        existing = self.vault.find_original(entity.text)
        if existing is not None:
            return existing

        if action is PolicyAction.REDACT:
            replacement = f"[REDACTED_{entity.type}]"
            restore = False
        elif self.mode in {"placeholder", "semantic_placeholder"}:
            replacement = self._placeholder(entity.type)
            restore = True
        elif self.mode == "surrogate":
            replacement = self.surrogates.generate(entity.type)
            restore = True
        else:
            replacement = f"[REDACTED_{entity.type}]"
            restore = False

        item = MappingItem(entity.type, entity.text, replacement, restore)
        self.vault.add(item)
        return item

    def mask_text(self, text: str, entities: list[Entity]) -> str:
        if RESERVED_TOKEN_PATTERN.search(text):
            raise ReservedTokenInjection
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

    def mask_text_with_actions(
        self,
        text: str,
        entities: list[Entity],
        actions: list[PrivacyAction],
    ) -> str:
        """Apply explicit Policy Module v2 decisions to detected spans."""
        if len(entities) != len(actions):
            raise ValueError("each entity must have exactly one privacy action")
        if RESERVED_TOKEN_PATTERN.search(text):
            raise ReservedTokenInjection

        replacements: list[tuple[int, int, str]] = []
        blocked: list[str] = []
        for entity, action in zip(entities, actions, strict=True):
            if action in {
                PrivacyAction.BLOCK,
                PrivacyAction.REQUIRE_REVIEW,
                PrivacyAction.GENERALIZE,
                PrivacyAction.HASH,
            }:
                blocked.append(entity.type)
                continue
            if action is PrivacyAction.ALLOW:
                continue

            existing = self.vault.find_original(entity.text)
            if existing is not None:
                item = existing
            elif action is PrivacyAction.REDACT:
                item = MappingItem(
                    entity.type,
                    entity.text,
                    f"[REDACTED_{entity.type}]",
                    False,
                )
                self.vault.add(item)
            elif action is PrivacyAction.SURROGATE:
                item = MappingItem(
                    entity.type,
                    entity.text,
                    self.surrogates.generate(entity.type),
                    True,
                )
                self.vault.add(item)
            else:
                # TOKENIZE preserves the explicitly selected compatibility
                # mode while opaque placeholder remains the secure default.
                item = self._replacement(entity, PolicyAction.MASK)
                if item is None:  # pragma: no cover - MASK cannot produce None
                    raise RuntimeError("tokenization did not produce a mapping")
            replacements.append((entity.start, entity.end, item.replacement))

        if blocked:
            raise PolicyBlocked(list(dict.fromkeys(blocked)))

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
