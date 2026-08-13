from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

import yaml

from app.masking.entity_types import EntityType
from app.privacy.models import (
    DataClass,
    PrivacyAction,
    PrivacyDirection,
    RiskBucket,
    TokenScope,
)
from app.privacy.policy.models import (
    PolicyDocumentV2,
    PolicyRule,
    PolicySchemaError,
    PublicAssertionScope,
    PublicDataAssertion,
    RuleConditions,
)

_T = TypeVar("_T")

_KNOWN_ENTITY_TYPES = frozenset(item.value for item in EntityType) | frozenset(
    {
        "ACCOUNT_NUMBER",
        "ADDRESS",
        "BIC",
        "CONNECTION_STRING",
        "DATE_OF_BIRTH",
        "IBAN",
        "IPV6",
        "JWT",
        "PASSWORD",
        "PRIVATE_KEY",
        "SWIFT",
    }
)
_PUBLIC_ASSERTION_ENTITY_TYPES = frozenset({"DOMAIN", "EMAIL", "LOCATION", "ORG", "PERSON", "URL"})
_ROOT_KEYS = frozenset({"version", "defaults", "rules", "public_data_assertions"})
_DEFAULT_KEYS = frozenset({"action", "reason", "obligations"})
_RULE_KEYS = frozenset({"id", "priority", "action", "reason", "obligations", "conditions"})
_CONDITION_KEYS = frozenset(
    {
        "entity_types",
        "data_classes",
        "tenants",
        "applications",
        "routes",
        "directions",
        "providers",
        "models",
        "jurisdictions",
        "purposes",
        "json_paths",
        "roles",
        "recognizers",
        "token_scopes",
        "risk_buckets",
        "min_confidence",
        "max_confidence",
        "min_risk_score",
        "max_risk_score",
    }
)
_ASSERTION_KEYS = frozenset(
    {
        "id",
        "entity_type",
        "value_sha256",
        "action",
        "reason",
        "obligations",
        "scope",
        "expires_at",
        "provenance",
    }
)
_ASSERTION_SCOPE_KEYS = frozenset(
    {
        "tenants",
        "applications",
        "directions",
        "providers",
        "purposes",
        "routes",
        "models",
        "jurisdictions",
    }
)


class _StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _StrictSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise PolicySchemaError("policy mapping keys must be scalar") from exc
        if duplicate:
            raise PolicySchemaError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _mapping(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise PolicySchemaError(f"{where} must be a string-keyed mapping")
    return value


def _reject_unknown(mapping: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise PolicySchemaError(f"{where} contains unknown keys: {', '.join(unknown)}")


def _required_string(mapping: Mapping[str, Any], key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PolicySchemaError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def _string_list(
    value: object,
    where: str,
    *,
    required: bool = False,
) -> tuple[str, ...]:
    if value is None and not required:
        return ()
    if not isinstance(value, list) or not value:
        raise PolicySchemaError(f"{where} must be a non-empty list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise PolicySchemaError(f"{where} must contain only non-empty strings")
    normalized = tuple(item.strip() for item in value)
    if len(set(normalized)) != len(normalized):
        raise PolicySchemaError(f"{where} contains duplicate values")
    return normalized


def _enum_value(enum_type: type[_T], value: object, where: str) -> _T:
    if not isinstance(value, str):
        raise PolicySchemaError(f"{where} must be a string")
    try:
        return enum_type(value)  # type: ignore[call-arg]
    except ValueError as exc:
        raise PolicySchemaError(f"{where} has unknown value {value!r}") from exc


def _enum_set(enum_type: type[_T], value: object, where: str) -> frozenset[_T]:
    return frozenset(_enum_value(enum_type, item, where) for item in _string_list(value, where))


def _number(
    value: object,
    where: str,
    *,
    minimum: float,
    maximum: float,
    integer: bool = False,
) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicySchemaError(f"{where} must be numeric")
    if integer and not isinstance(value, int):
        raise PolicySchemaError(f"{where} must be an integer")
    if not minimum <= value <= maximum:
        raise PolicySchemaError(f"{where} must be between {minimum} and {maximum}")
    return value


def _known_entities(value: object, where: str) -> frozenset[str]:
    raw_entities = _string_list(value, where)
    entities = frozenset(item.upper() for item in raw_entities)
    if len(entities) != len(raw_entities):
        raise PolicySchemaError(f"{where} contains duplicate normalized entity types")
    unknown = sorted(entities - _KNOWN_ENTITY_TYPES)
    if unknown:
        raise PolicySchemaError(f"{where} contains unknown entity types: {', '.join(unknown)}")
    return entities


def _parse_conditions(raw: object, where: str) -> RuleConditions:
    mapping = _mapping(raw, where)
    _reject_unknown(mapping, _CONDITION_KEYS, where)
    min_confidence = _number(
        mapping.get("min_confidence"),
        f"{where}.min_confidence",
        minimum=0.0,
        maximum=1.0,
    )
    max_confidence = _number(
        mapping.get("max_confidence"),
        f"{where}.max_confidence",
        minimum=0.0,
        maximum=1.0,
    )
    min_risk = _number(
        mapping.get("min_risk_score"),
        f"{where}.min_risk_score",
        minimum=0,
        maximum=100,
        integer=True,
    )
    max_risk = _number(
        mapping.get("max_risk_score"),
        f"{where}.max_risk_score",
        minimum=0,
        maximum=100,
        integer=True,
    )
    if min_confidence is not None and max_confidence is not None:
        if min_confidence > max_confidence:
            raise PolicySchemaError(f"{where} confidence range is inverted")
    if min_risk is not None and max_risk is not None and min_risk > max_risk:
        raise PolicySchemaError(f"{where} risk-score range is inverted")

    return RuleConditions(
        entity_types=_known_entities(mapping.get("entity_types"), f"{where}.entity_types"),
        data_classes=_enum_set(DataClass, mapping.get("data_classes"), f"{where}.data_classes"),
        tenants=frozenset(_string_list(mapping.get("tenants"), f"{where}.tenants")),
        applications=frozenset(_string_list(mapping.get("applications"), f"{where}.applications")),
        routes=frozenset(_string_list(mapping.get("routes"), f"{where}.routes")),
        directions=_enum_set(PrivacyDirection, mapping.get("directions"), f"{where}.directions"),
        providers=frozenset(_string_list(mapping.get("providers"), f"{where}.providers")),
        models=frozenset(_string_list(mapping.get("models"), f"{where}.models")),
        jurisdictions=frozenset(
            _string_list(mapping.get("jurisdictions"), f"{where}.jurisdictions")
        ),
        purposes=frozenset(_string_list(mapping.get("purposes"), f"{where}.purposes")),
        json_paths=_string_list(mapping.get("json_paths"), f"{where}.json_paths"),
        roles=frozenset(_string_list(mapping.get("roles"), f"{where}.roles")),
        recognizers=frozenset(_string_list(mapping.get("recognizers"), f"{where}.recognizers")),
        token_scopes=_enum_set(TokenScope, mapping.get("token_scopes"), f"{where}.token_scopes"),
        risk_buckets=_enum_set(RiskBucket, mapping.get("risk_buckets"), f"{where}.risk_buckets"),
        min_confidence=float(min_confidence) if min_confidence is not None else None,
        max_confidence=float(max_confidence) if max_confidence is not None else None,
        min_risk_score=int(min_risk) if min_risk is not None else None,
        max_risk_score=int(max_risk) if max_risk is not None else None,
    )


def _parse_rule(raw: object, index: int) -> PolicyRule:
    where = f"rules[{index}]"
    mapping = _mapping(raw, where)
    _reject_unknown(mapping, _RULE_KEYS, where)
    rule_id = _required_string(mapping, "id", where)
    priority = _number(
        mapping.get("priority"), f"{where}.priority", minimum=0, maximum=1_000_000, integer=True
    )
    if priority is None:
        raise PolicySchemaError(f"{where}.priority is required")
    reason = _required_string(mapping, "reason", where)
    obligations = _string_list(mapping.get("obligations"), f"{where}.obligations")
    conditions = _parse_conditions(mapping.get("conditions"), f"{where}.conditions")
    return PolicyRule(
        rule_id=rule_id,
        priority=int(priority),
        action=_enum_value(PrivacyAction, mapping.get("action"), f"{where}.action"),
        reason=reason,
        obligations=obligations,
        conditions=conditions,
    )


def _parse_datetime(value: object, where: str) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise PolicySchemaError(f"{where} must be ISO-8601") from exc
    else:
        raise PolicySchemaError(f"{where} must be ISO-8601")
    if result.tzinfo is None or result.utcoffset() is None:
        raise PolicySchemaError(f"{where} must include a timezone")
    return result.astimezone(timezone.utc)


def _required_scope_values(mapping: Mapping[str, Any], key: str, where: str) -> frozenset[str]:
    return frozenset(_string_list(mapping.get(key), f"{where}.{key}", required=True))


def _parse_assertion(raw: object, index: int) -> PublicDataAssertion:
    where = f"public_data_assertions[{index}]"
    mapping = _mapping(raw, where)
    _reject_unknown(mapping, _ASSERTION_KEYS, where)
    entity_type = _required_string(mapping, "entity_type", where).upper()
    if entity_type not in _PUBLIC_ASSERTION_ENTITY_TYPES:
        raise PolicySchemaError(f"{where}.entity_type is not eligible for public assertion")
    value_sha256 = _required_string(mapping, "value_sha256", where).lower()
    if len(value_sha256) != 64 or any(char not in "0123456789abcdef" for char in value_sha256):
        raise PolicySchemaError(f"{where}.value_sha256 must be a SHA-256 hex digest")
    action = _enum_value(PrivacyAction, mapping.get("action"), f"{where}.action")
    if action is not PrivacyAction.ALLOW:
        raise PolicySchemaError(f"{where}.action must be ALLOW")

    scope_where = f"{where}.scope"
    scope_mapping = _mapping(mapping.get("scope"), scope_where)
    _reject_unknown(scope_mapping, _ASSERTION_SCOPE_KEYS, scope_where)
    scope = PublicAssertionScope(
        tenants=_required_scope_values(scope_mapping, "tenants", scope_where),
        applications=_required_scope_values(scope_mapping, "applications", scope_where),
        directions=frozenset(
            _enum_value(PrivacyDirection, value, f"{scope_where}.directions")
            for value in _string_list(
                scope_mapping.get("directions"),
                f"{scope_where}.directions",
                required=True,
            )
        ),
        providers=_required_scope_values(scope_mapping, "providers", scope_where),
        purposes=_required_scope_values(scope_mapping, "purposes", scope_where),
        routes=frozenset(_string_list(scope_mapping.get("routes"), f"{scope_where}.routes")),
        models=frozenset(_string_list(scope_mapping.get("models"), f"{scope_where}.models")),
        jurisdictions=frozenset(
            _string_list(scope_mapping.get("jurisdictions"), f"{scope_where}.jurisdictions")
        ),
    )
    return PublicDataAssertion(
        assertion_id=_required_string(mapping, "id", where),
        entity_type=entity_type,
        value_sha256=value_sha256,
        action=action,
        reason=_required_string(mapping, "reason", where),
        obligations=_string_list(mapping.get("obligations"), f"{where}.obligations"),
        scope=scope,
        expires_at=_parse_datetime(mapping.get("expires_at"), f"{where}.expires_at"),
        provenance=_required_string(mapping, "provenance", where),
    )


def _ensure_unique(items: Iterable[tuple[object, str]], label: str) -> None:
    seen: set[object] = set()
    for value, where in items:
        if value in seen:
            raise PolicySchemaError(f"duplicate {label} {value!r} at {where}")
        seen.add(value)


def load_policy_v2(path: Path) -> PolicyDocumentV2:
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_StrictSafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PolicySchemaError(f"cannot load policy: {exc}") from exc
    root = _mapping(raw, "policy")
    _reject_unknown(root, _ROOT_KEYS, "policy")
    if root.get("version") != 2:
        raise PolicySchemaError("policy.version must be integer 2")

    defaults = _mapping(root.get("defaults"), "defaults")
    _reject_unknown(defaults, _DEFAULT_KEYS, "defaults")
    default_action = _enum_value(PrivacyAction, defaults.get("action"), "defaults.action")
    if default_action not in {PrivacyAction.BLOCK, PrivacyAction.REQUIRE_REVIEW}:
        raise PolicySchemaError("defaults.action must fail closed with BLOCK or REQUIRE_REVIEW")

    raw_rules = root.get("rules", [])
    raw_assertions = root.get("public_data_assertions", [])
    if not isinstance(raw_rules, list):
        raise PolicySchemaError("rules must be a list")
    if not isinstance(raw_assertions, list):
        raise PolicySchemaError("public_data_assertions must be a list")
    rules = tuple(_parse_rule(item, index) for index, item in enumerate(raw_rules))
    assertions = tuple(_parse_assertion(item, index) for index, item in enumerate(raw_assertions))
    _ensure_unique(
        ((rule.rule_id, f"rules[{index}]") for index, rule in enumerate(rules)),
        "rule id",
    )
    _ensure_unique(
        ((rule.priority, f"rules[{index}]") for index, rule in enumerate(rules)),
        "rule priority",
    )
    _ensure_unique(
        (
            (assertion.assertion_id, f"public_data_assertions[{index}]")
            for index, assertion in enumerate(assertions)
        ),
        "public assertion id",
    )
    _ensure_unique(
        (
            (
                (assertion.entity_type, assertion.value_sha256, assertion.scope),
                f"public_data_assertions[{index}]",
            )
            for index, assertion in enumerate(assertions)
        ),
        "public assertion target and scope",
    )
    return PolicyDocumentV2(
        version="2",
        default_action=default_action,
        default_reason=_required_string(defaults, "reason", "defaults"),
        default_obligations=_string_list(defaults.get("obligations"), "defaults.obligations"),
        rules=tuple(sorted(rules, key=lambda rule: rule.priority, reverse=True)),
        public_data_assertions=assertions,
    )
