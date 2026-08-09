from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable

import yaml


class PolicyAction(StrEnum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


class PolicyBlocked(Exception):
    def __init__(self, entity_types: list[str]) -> None:
        self.entity_types = entity_types
        super().__init__("Request blocked because sensitive data was detected")


class PolicyEngine:
    def __init__(
        self,
        policy_file: Path,
        *,
        block_api_keys: bool = True,
        block_secrets: bool = True,
        block_credit_cards: bool = False,
        public_email_allowlist: Iterable[str] = (),
        public_email_domain_allowlist: Iterable[str] = (),
        public_person_allowlist: Iterable[str] = (),
    ) -> None:
        self.rules: dict[str, PolicyAction] = {}
        self.public_email_allowlist = {
            value.strip().casefold() for value in public_email_allowlist if value.strip()
        }
        self.public_email_domain_allowlist = {
            value.strip().lstrip("@").casefold()
            for value in public_email_domain_allowlist
            if value.strip()
        }
        self.public_person_allowlist = {
            " ".join(value.split()).casefold() for value in public_person_allowlist if value.strip()
        }
        raw = yaml.safe_load(policy_file.read_text(encoding="utf-8")) or {}
        for rule in raw.get("rules", []):
            try:
                self.rules[str(rule["entity_type"]).upper()] = PolicyAction(
                    str(rule["action"]).upper()
                )
            except (KeyError, ValueError):
                continue
        if not block_api_keys or not block_secrets:
            self.rules["API_KEY"] = PolicyAction.MASK
        elif block_api_keys:
            self.rules["API_KEY"] = PolicyAction.BLOCK
        if block_credit_cards:
            self.rules["CARD_NUMBER"] = PolicyAction.BLOCK

    def action_for(self, entity_type: str) -> PolicyAction:
        # Unknown detected entity types are masked conservatively by default.
        return self.rules.get(entity_type.upper(), PolicyAction.MASK)

    def is_public_allowlisted(self, entity_type: str, value: str) -> bool:
        normalized_type = entity_type.upper()
        if normalized_type == "EMAIL":
            normalized_email = value.strip().casefold()
            if normalized_email in self.public_email_allowlist:
                return True
            _, separator, domain = normalized_email.rpartition("@")
            return bool(separator and domain in self.public_email_domain_allowlist)
        if normalized_type == "PERSON":
            return " ".join(value.split()).casefold() in self.public_person_allowlist
        return False

    def action_for_entity(self, entity_type: str, value: str) -> PolicyAction:
        if self.is_public_allowlisted(entity_type, value):
            return PolicyAction.ALLOW
        return self.action_for(entity_type)

    def actions_for(self, entity_types: list[str]) -> dict[str, PolicyAction]:
        return {entity_type: self.action_for(entity_type) for entity_type in entity_types}

    def inspect(self, entity_types: list[str]) -> tuple[PolicyAction, list[str]]:
        actions = [self.action_for(entity_type) for entity_type in entity_types]
        blocked = list(
            dict.fromkeys(
                entity_type
                for entity_type, action in zip(entity_types, actions)
                if action is PolicyAction.BLOCK
            )
        )
        if blocked:
            return PolicyAction.BLOCK, blocked
        if any(action is PolicyAction.REDACT for action in actions):
            return PolicyAction.REDACT, []
        if any(action is PolicyAction.MASK for action in actions):
            return PolicyAction.MASK, []
        return PolicyAction.ALLOW, []

    def to_dict(self) -> dict[str, Any]:
        return {key: value.value for key, value in self.rules.items()}
