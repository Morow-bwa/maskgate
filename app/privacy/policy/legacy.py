from __future__ import annotations

from collections.abc import Mapping

from app.privacy.models import PrivacyAction
from app.privacy.policy.models import (
    PolicyDocumentV2,
    PolicyRule,
    PolicySchemaError,
    RuleConditions,
)

_LEGACY_ACTIONS: dict[str, PrivacyAction] = {
    "ALLOW": PrivacyAction.ALLOW,
    "MASK": PrivacyAction.TOKENIZE,
    "REDACT": PrivacyAction.REDACT,
    "BLOCK": PrivacyAction.BLOCK,
}


class LegacyPolicyAdapter:
    """Narrow Adapter from legacy entity/action maps to Policy Module v2."""

    def adapt(self, actions: Mapping[str, object]) -> PolicyDocumentV2:
        rules: list[PolicyRule] = []
        for index, (entity_type, legacy_action) in enumerate(sorted(actions.items())):
            action_name = getattr(legacy_action, "value", legacy_action)
            if not isinstance(action_name, str) or action_name.upper() not in _LEGACY_ACTIONS:
                raise PolicySchemaError(
                    f"legacy action for {entity_type!r} is unknown: {action_name!r}"
                )
            normalized_entity = entity_type.strip().upper()
            if not normalized_entity:
                raise PolicySchemaError("legacy entity type cannot be empty")
            rules.append(
                PolicyRule(
                    rule_id=f"legacy-{normalized_entity.casefold().replace('_', '-')}",
                    priority=100_000 - index,
                    action=_LEGACY_ACTIONS[action_name.upper()],
                    reason="adapted_legacy_policy_rule",
                    obligations=("audit_decision", "migrate_to_policy_v2"),
                    conditions=RuleConditions(entity_types=frozenset({normalized_entity})),
                )
            )
        return PolicyDocumentV2(
            version="2-legacy-adapter-1",
            default_action=PrivacyAction.BLOCK,
            default_reason="legacy_policy_has_no_explicit_rule",
            default_obligations=("audit_decision", "migrate_to_policy_v2"),
            rules=tuple(rules),
            public_data_assertions=(),
        )
