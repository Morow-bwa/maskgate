from __future__ import annotations

import re

import pytest

from app.masking.anonymizer import MaskingSession, VaultCapacityExceeded
from app.masking.detector import Entity
from app.policies.policy_engine import PolicyEngine


def _email_entity(value: str) -> Entity:
    return Entity("EMAIL", value, 0, len(value))


def test_thousands_of_opaque_tokens_are_unique_bounded_and_metadata_free(settings) -> None:
    session = MaskingSession(
        "placeholder",
        PolicyEngine(settings.policy_file),
        token_namespace="tenantA_openai",
        max_mappings=2_000,
    )
    originals = [f"owner{index}@example.com" for index in range(2_000)]

    tokens = {session.mask_text(original, [_email_entity(original)]) for original in originals}

    assert len(tokens) == 2_000
    assert all(re.fullmatch(r"<MG:[A-Z2-7]{26}>", token) for token in tokens)
    assert all("EMAIL" not in token for token in tokens)
    assert all("tenantA" not in token and "openai" not in token for token in tokens)

    overflow = "overflow@example.com"
    with pytest.raises(VaultCapacityExceeded):
        session.mask_text(overflow, [_email_entity(overflow)])
