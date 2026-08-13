from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.privacy.models import (
    DataClass,
    PrivacyAction,
    PrivacyDetection,
    PrivacyDirection,
    RiskAssessment,
    RiskBucket,
    TokenScope,
)
from app.privacy.policy import (
    LegacyPolicyAdapter,
    PolicyContext,
    PolicyEngineV2,
    PolicySchemaError,
    hash_public_value,
    load_policy_v2,
)

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=timezone.utc)


def _write_policy(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(source, encoding="utf-8")
    return path


def _detection(
    entity_type: str = "EMAIL",
    data_class: DataClass = DataClass.DIRECT_PII,
) -> PrivacyDetection:
    return PrivacyDetection(
        entity_type=entity_type,
        data_class=data_class,
        start=0,
        end=10,
        confidence=0.96,
        recognizer="email-regex-v2",
    )


def _context(**overrides: object) -> PolicyContext:
    values: dict[str, object] = {
        "tenant": "tenant-a",
        "application": "support-chat",
        "route": "/v1/chat/completions",
        "direction": PrivacyDirection.INPUT,
        "provider": "openai",
        "model": "gpt-test",
        "jurisdiction": "EU",
        "purpose": "customer-support",
        "json_path": ("messages", 0, "content"),
        "role": "user",
        "confidence": 0.96,
        "risk": RiskAssessment(
            score=64,
            bucket=RiskBucket.HIGH,
            signals=("class:DIRECT_PII",),
            data_classes=frozenset({DataClass.DIRECT_PII}),
        ),
        "recognizer": "email-regex-v2",
        "token_scope": TokenScope.REQUEST,
    }
    values.update(overrides)
    return PolicyContext(**values)  # type: ignore[arg-type]


def _base_policy(rules: str = "[]", assertions: str = "[]") -> str:
    return f"""
version: 2
defaults:
  action: BLOCK
  reason: no_explicit_policy_match
  obligations: [audit_decision]
rules: {rules}
public_data_assertions: {assertions}
"""


def test_no_matching_rule_fails_closed(tmp_path: Path) -> None:
    policy = load_policy_v2(_write_policy(tmp_path, _base_policy()))

    decision = PolicyEngineV2(policy, now=lambda: NOW).decide(
        _detection(), _context(), value="private@example.com"
    )

    assert decision.action is PrivacyAction.BLOCK
    assert decision.reason == "no_explicit_policy_match"
    assert decision.policy_version == "2"
    assert decision.obligations == ("audit_decision",)


def test_highest_explicit_priority_wins_and_returns_auditable_decision(
    tmp_path: Path,
) -> None:
    rules = """
      - id: broad-direct-pii
        priority: 100
        action: REDACT
        reason: broad_direct_pii_rule
        obligations: [audit_decision]
        conditions:
          data_classes: [DIRECT_PII]
      - id: support-email
        priority: 200
        action: TOKENIZE
        reason: approved_support_flow
        obligations: [vault_request_scope, audit_decision]
        conditions:
          entity_types: [EMAIL]
          tenants: [tenant-a]
          applications: [support-chat]
          routes: [/v1/chat/completions]
          directions: [INPUT]
          providers: [openai]
          models: [gpt-test]
          jurisdictions: [EU]
          purposes: [customer-support]
          json_paths: [messages.*.content]
          roles: [user]
          recognizers: [email-regex-v2]
          token_scopes: [request]
          min_confidence: 0.9
          risk_buckets: [HIGH]
          min_risk_score: 50
    """
    policy = load_policy_v2(_write_policy(tmp_path, _base_policy(rules)))

    decision = PolicyEngineV2(policy, now=lambda: NOW).decide(
        _detection(), _context(), value="private@example.com"
    )

    assert decision.action is PrivacyAction.TOKENIZE
    assert decision.rule_id == "support-email"
    assert decision.reason == "approved_support_flow"
    assert decision.obligations == ("vault_request_scope", "audit_decision")


@pytest.mark.parametrize(
    "source",
    [
        # Duplicate mapping key must not be silently overwritten by PyYAML.
        "version: 2\nversion: 2\ndefaults: {action: BLOCK}\nrules: []\n",
        _base_policy().replace("rules: []", "rules: []\nunknown_root: true"),
        _base_policy("[{id: bad, priority: 1, action: EXFILTRATE, conditions: {}}]"),
        _base_policy("[{id: bad, priority: 1, action: BLOCK, mystery: true, conditions: {}}]"),
        _base_policy("[{id: bad, priority: 1, action: BLOCK, conditions: {mystery: [x]}}]"),
        _base_policy(
            "[{id: bad, priority: 1, action: BLOCK, conditions: {data_classes: [UNKNOWN]}}]"
        ),
        _base_policy(
            "[{id: bad, priority: 1, action: BLOCK, conditions: {entity_types: [UNKNOWN]}}]"
        ),
    ],
)
def test_policy_schema_rejects_malformed_or_unknown_input(tmp_path: Path, source: str) -> None:
    with pytest.raises(PolicySchemaError):
        load_policy_v2(_write_policy(tmp_path, source))


@pytest.mark.parametrize(
    "rules",
    [
        """
          - {id: duplicate, priority: 10, action: BLOCK, conditions: {}}
          - {id: duplicate, priority: 20, action: REDACT, conditions: {}}
        """,
        """
          - {id: first, priority: 10, action: BLOCK, conditions: {}}
          - {id: second, priority: 10, action: REDACT, conditions: {}}
        """,
    ],
)
def test_rule_identity_and_precedence_must_be_unambiguous(tmp_path: Path, rules: str) -> None:
    with pytest.raises(PolicySchemaError):
        load_policy_v2(_write_policy(tmp_path, _base_policy(rules)))


def test_public_data_assertion_is_exact_scoped_expiring_and_provenanced(
    tmp_path: Path,
) -> None:
    value_hash = hash_public_value("EMAIL", "Press@Example.org")
    assertions = f"""
      - id: press-address
        entity_type: EMAIL
        value_sha256: {value_hash}
        action: ALLOW
        reason: published_press_contact
        obligations: [audit_public_assertion]
        scope:
          tenants: [tenant-a]
          applications: [support-chat]
          routes: [/v1/chat/completions]
          directions: [INPUT]
          providers: [openai]
          models: [gpt-test]
          jurisdictions: [EU]
          purposes: [customer-support]
        expires_at: 2026-09-01T00:00:00Z
        provenance: https://example.org/contact
    """
    policy = load_policy_v2(_write_policy(tmp_path, _base_policy(assertions=assertions)))
    engine = PolicyEngineV2(policy, now=lambda: NOW)

    allowed = engine.decide(_detection(), _context(), value=" press@example.org ")
    wrong_tenant = engine.decide(
        _detection(), _context(tenant="tenant-b"), value="press@example.org"
    )
    wrong_provider = engine.decide(
        _detection(), _context(provider="anthropic"), value="press@example.org"
    )

    assert allowed.action is PrivacyAction.ALLOW
    assert allowed.assertion_id == "press-address"
    assert allowed.reason == "published_press_contact"
    assert wrong_tenant.action is PrivacyAction.BLOCK
    assert wrong_provider.action is PrivacyAction.BLOCK


def test_expired_public_assertion_does_not_allow_value(tmp_path: Path) -> None:
    value_hash = hash_public_value("PERSON", "Jane Austen")
    assertions = f"""
      - id: known-author
        entity_type: PERSON
        value_sha256: {value_hash}
        action: ALLOW
        reason: cited_public_author
        obligations: [audit_public_assertion]
        scope:
          tenants: [tenant-a]
          applications: [support-chat]
          directions: [INPUT]
          providers: [openai]
          purposes: [customer-support]
        expires_at: 2026-08-01T00:00:00Z
        provenance: https://example.org/authors/jane-austen
    """
    policy = load_policy_v2(_write_policy(tmp_path, _base_policy(assertions=assertions)))

    decision = PolicyEngineV2(policy, now=lambda: NOW).decide(
        _detection("PERSON"), _context(), value="Jane Austen"
    )

    assert decision.action is PrivacyAction.BLOCK


def test_public_assertion_cannot_override_contextual_block(tmp_path: Path) -> None:
    value_hash = hash_public_value("EMAIL", "press@example.org")
    rules = """
      - id: block-sensitive-tool-path
        priority: 100
        action: BLOCK
        reason: sensitive_tool_path
        obligations: [audit_decision]
        conditions:
          entity_types: [EMAIL]
          json_paths: [tools.*]
    """
    assertions = f"""
      - id: press-address
        entity_type: EMAIL
        value_sha256: {value_hash}
        action: ALLOW
        reason: published_press_contact
        obligations: [audit_public_assertion]
        scope:
          tenants: [tenant-a]
          applications: [support-chat]
          directions: [INPUT]
          providers: [openai]
          purposes: [customer-support]
        expires_at: 2026-09-01T00:00:00Z
        provenance: https://example.org/contact
    """
    policy = load_policy_v2(
        _write_policy(tmp_path, _base_policy(rules=rules, assertions=assertions))
    )
    context = _context(json_path=("tools", 0, "description"))

    decision = PolicyEngineV2(policy, now=lambda: NOW).decide(
        _detection(), context, value="press@example.org"
    )

    assert decision.action is PrivacyAction.BLOCK
    assert decision.rule_id == "block-sensitive-tool-path"


def test_context_blind_public_assertion_is_rejected(tmp_path: Path) -> None:
    value_hash = hash_public_value("PERSON", "Jane Austen")
    assertions = f"""
      - id: unsafe-global-name
        entity_type: PERSON
        value_sha256: {value_hash}
        action: ALLOW
        reason: famous_writer
        obligations: [audit_public_assertion]
        scope:
          tenants: [tenant-a]
        expires_at: 2026-09-01T00:00:00Z
        provenance: https://example.org/authors/jane-austen
    """

    with pytest.raises(PolicySchemaError):
        load_policy_v2(_write_policy(tmp_path, _base_policy(assertions=assertions)))


def test_legacy_adapter_maps_mask_to_tokenize_without_weakening_default() -> None:
    policy = LegacyPolicyAdapter().adapt(
        {"EMAIL": "MASK", "API_KEY": "BLOCK", "CARD_NUMBER": "REDACT"}
    )
    engine = PolicyEngineV2(policy, now=lambda: NOW)

    email = engine.decide(_detection(), _context(), value="private@example.com")
    unknown = engine.decide(_detection("PERSON"), _context(), value="Private Person")

    assert policy.version.startswith("2-legacy-adapter")
    assert email.action is PrivacyAction.TOKENIZE
    assert unknown.action is PrivacyAction.BLOCK


def test_policy_context_rejects_missing_security_identity() -> None:
    with pytest.raises(ValueError):
        _context(tenant="")
