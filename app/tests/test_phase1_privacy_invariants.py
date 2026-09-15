from __future__ import annotations

import base64
import re
from copy import deepcopy

import pytest

from app.masking.anonymizer import (
    MappingItem,
    MaskingSession,
    ReservedTokenInjection,
    VaultCapacityExceeded,
)
from app.masking.detector import RegexDetector
from app.masking.rehydrator import rehydrate
from app.masking.surrogate_generator import SurrogateGenerator
from app.policies.policy_engine import PolicyEngine
from app.privacy.detection import DetectorEnsemble
from app.privacy.models import DetectorProfile
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.vault import InMemoryVault, VaultBudget
from app.privacy.wire import FinalWirePrivacyGuard, WirePrivacyViolation


def test_reversible_surrogates_never_wrap_or_collide() -> None:
    generator = SurrogateGenerator()

    generated = [generator.generate("EMAIL") for _ in range(100)]

    assert len(generated) == len(set(generated))


def test_default_placeholder_is_opaque_and_collision_resistant(settings) -> None:
    policy = PolicyEngine(settings.policy_file, block_api_keys=False)
    session = MaskingSession("placeholder", policy)
    detector = RegexDetector()
    text = "Contact alice@example.com or bob@example.com"

    masked = session.mask_text(text, detector.detect(text))
    tokens = [item.replacement for item in session.items]

    assert all(re.fullmatch(r"<MG:[A-Z2-7]{26}>", token) for token in tokens)
    assert len(tokens) == len(set(tokens)) == 2
    assert "EMAIL" not in masked
    assert "_1" not in masked


def test_structural_rehydration_restores_dictionary_keys() -> None:
    mapping = [MappingItem("EMAIL", "owner@example.com", "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>")]

    restored = rehydrate(
        {"<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>": {"value": "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"}},
        mapping,
    )

    assert restored == {"owner@example.com": {"value": "owner@example.com"}}


def test_vault_deepcopy_has_independent_lock_and_indexes() -> None:
    vault = InMemoryVault(VaultBudget())
    vault.add(MappingItem("EMAIL", "first@example.com", "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"))

    cloned = deepcopy(vault)
    cloned.add(MappingItem("EMAIL", "second@example.com", "<MG:BBBBBBBBBBBBBBBBBBBBBBBBBB>"))

    assert len(vault.items) == 1
    assert len(cloned.items) == 2


def test_final_wire_guard_checks_exact_serialized_body() -> None:
    guard = FinalWirePrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT))

    checked = guard.check(
        provider="openai-chat",
        payload={
            "messages": [{"role": "user", "content": "Hello <MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"}]
        },
        approved_tokens={"<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"},
    )

    assert b"<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>" in checked.body
    assert checked.provider == "openai-chat"


def test_final_wire_guard_rejects_raw_pii_and_injected_tokens() -> None:
    guard = FinalWirePrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT))

    with pytest.raises(WirePrivacyViolation, match="EMAIL"):
        guard.check(
            provider="openai-chat",
            payload={"messages": [{"role": "user", "content": "alice@example.com"}]},
        )


def test_final_wire_guard_rejects_reversibly_encoded_content() -> None:
    guard = FinalWirePrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT))
    encoded = base64.b64encode(b"alice@example.com").decode("ascii")

    with pytest.raises(WirePrivacyViolation, match="unsupported encoded content"):
        guard.check(
            provider="openai-chat",
            payload={"metadata": {"opaque": encoded}},
        )


def test_final_wire_guard_rejects_unclassified_numeric_data() -> None:
    guard = FinalWirePrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT))

    with pytest.raises(WirePrivacyViolation, match="unclassified numeric"):
        guard.check(
            provider="openai-chat",
            payload={"metadata": {"phone_as_number": 7_916_123_4567}},
        )

    checked = guard.check(
        provider="openai-chat",
        payload={"temperature": 0.2, "max_tokens": 100, "messages": []},
    )
    assert checked.payload["temperature"] == 0.2

    with pytest.raises(WirePrivacyViolation, match="encoded EMAIL"):
        guard.check(
            provider="openai-chat",
            payload={"metadata": {"escaped": "alice%40example%2Ecom"}},
        )

    with pytest.raises(WirePrivacyViolation, match="unrecognized MaskGate token"):
        guard.check(
            provider="openai-chat",
            payload={"messages": [{"role": "user", "content": "<MG:BBBBBBBBBBBBBBBBBBBBBBBBBB>"}]},
        )


def test_output_guard_redacts_new_provider_pii_before_authorized_rehydration() -> None:
    guard = OutputPrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT))
    mapping = [MappingItem("EMAIL", "owner@example.com", "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>")]
    provider_response = {
        "choices": [
            {
                "message": {
                    "content": (
                        "Known <MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>; generated stranger@example.net"
                    )
                }
            }
        ]
    }

    guarded = guard.process(provider_response, mapping)

    content = guarded["choices"][0]["message"]["content"]
    assert "owner@example.com" in content
    assert "stranger@example.net" not in content
    assert "[REDACTED_PROVIDER_EMAIL]" in content


def test_output_guard_never_restores_tokens_in_provider_metadata() -> None:
    guard = OutputPrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT))
    mapping = [MappingItem("EMAIL", "owner@example.com", "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>")]

    guarded = guard.process(
        {
            "id": "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>",
            "choices": [{"message": {"content": "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"}}],
        },
        mapping,
    )

    assert guarded["id"] == "[REDACTED_PROVIDER_TOKEN]"
    assert guarded["choices"][0]["message"]["content"] == "owner@example.com"


def test_vault_mapping_budget_fails_closed(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("placeholder", policy, max_mappings=1)
    detector = RegexDetector()
    session.mask_text("first@example.com", detector.detect("first@example.com"))

    with pytest.raises(VaultCapacityExceeded):
        session.mask_text("second@example.com", detector.detect("second@example.com"))


def test_user_supplied_reserved_token_is_rejected(settings) -> None:
    session = MaskingSession("placeholder", PolicyEngine(settings.policy_file))
    text = "Replay <MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"

    with pytest.raises(ReservedTokenInjection):
        session.mask_text(text, RegexDetector().detect(text))
