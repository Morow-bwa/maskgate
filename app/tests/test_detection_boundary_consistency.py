from __future__ import annotations

import pytest

from app.main import create_app
from app.masking.anonymizer import MappingItem
from app.privacy.detection import (
    DetectorCapabilityManifest,
    DetectorCapabilityMismatch,
    DetectorEnsemble,
    PrivacyDetector,
    ensure_terminal_capabilities,
)
from app.privacy.models import DetectionContext, DetectorProfile, PrivacyDetection
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.wire import FinalWirePrivacyGuard, WirePrivacyViolation


def test_detector_exposes_provider_independent_capability_manifest() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)

    assert isinstance(detector, PrivacyDetector)
    manifest = detector.capabilities()

    assert manifest.profile is DetectorProfile.STRICT
    assert "JWT" in manifest.entities
    assert "structured-secrets" in manifest.recognizers
    assert manifest.to_dict()["entities"] == sorted(manifest.entities)


def test_application_shares_one_privacy_detector_across_all_boundaries(settings) -> None:
    app = create_app(settings, llm_client=object())

    detector = app.state.privacy_detector
    assert app.state.privacy_pipeline.wire_guard.detector is detector
    assert app.state.privacy_pipeline.output_guard.detector is detector


class _ManifestDetector:
    def __init__(self, manifest: DetectorCapabilityManifest) -> None:
        self._manifest = manifest

    @property
    def profile(self) -> DetectorProfile:
        return self._manifest.profile

    def analyze(
        self,
        text: str,
        context: DetectionContext | None = None,
    ) -> list[PrivacyDetection]:
        return []

    def capabilities(self) -> DetectorCapabilityManifest:
        return self._manifest


class _AnalyzeOnlyDetector:
    def __init__(self, detector: DetectorEnsemble) -> None:
        self._detector = detector

    @property
    def profile(self) -> DetectorProfile:
        return self._detector.profile

    def analyze(
        self,
        text: str,
        context: DetectionContext | None = None,
    ) -> list[PrivacyDetection]:
        return self._detector.analyze(text, context)

    def capabilities(self) -> DetectorCapabilityManifest:
        return self._detector.capabilities()


def test_terminal_capability_invariant_rejects_weaker_profile_with_same_entities() -> None:
    strict = DetectorEnsemble(profile=DetectorProfile.STRICT)
    manifest = strict.capabilities()
    weaker = _ManifestDetector(
        DetectorCapabilityManifest(
            profile=DetectorProfile.BALANCED,
            entities=manifest.entities,
            recognizers=manifest.recognizers,
            minimum_confidence=manifest.minimum_confidence,
        )
    )

    with pytest.raises(DetectorCapabilityMismatch, match="profile is weaker"):
        ensure_terminal_capabilities(strict, wire=weaker, output=strict)


def test_terminal_capability_invariant_automatically_rejects_missing_entity() -> None:
    strict = DetectorEnsemble(profile=DetectorProfile.STRICT)
    manifest = strict.capabilities()
    omitted = next(iter(manifest.entities))
    weaker = _ManifestDetector(
        DetectorCapabilityManifest(
            profile=manifest.profile,
            entities=manifest.entities - {omitted},
            recognizers=manifest.recognizers,
            minimum_confidence=manifest.minimum_confidence,
        )
    )

    with pytest.raises(DetectorCapabilityMismatch, match="missing ingress capabilities"):
        ensure_terminal_capabilities(strict, wire=weaker, output=strict)


@pytest.mark.parametrize(
    ("entity_type", "malicious_value"),
    [
        ("IBAN", "GB82 WEST 1234 5698 7654 32"),
        ("SNILS", "112-233-445 95"),
        ("PASSPORT", "паспорт: серия 4510, номер 123456"),
        (
            "JWT",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234567890",
        ),
        ("IP_ADDRESS", "2001:db8:85a3::8a2e:370:7334"),
    ],
)
def test_final_wire_guard_rejects_sensitive_value_reintroduced_after_adapter(
    entity_type: str,
    malicious_value: str,
) -> None:
    detector = _AnalyzeOnlyDetector(DetectorEnsemble(profile=DetectorProfile.STRICT))
    guard = FinalWirePrivacyGuard(detector)

    with pytest.raises(WirePrivacyViolation, match=entity_type):
        guard.check(
            provider="openai-chat",
            payload={"messages": [{"role": "user", "content": malicious_value}]},
        )


def test_responses_wire_guard_allows_only_reviewed_numeric_settings() -> None:
    guard = FinalWirePrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT))

    checked = guard.check(
        provider="openai-responses",
        payload={
            "model": "gpt-test",
            "input": [],
            "max_output_tokens": 128,
            "temperature": 0.2,
            "top_p": 0.9,
        },
    )
    assert checked.payload["max_output_tokens"] == 128

    with pytest.raises(WirePrivacyViolation, match="unclassified numeric"):
        guard.check(
            provider="openai-responses",
            payload={"model": "gpt-test", "input": [], "customer_number": 123456},
        )


@pytest.mark.parametrize(
    ("entity_type", "provider_text", "raw_sensitive_value"),
    [
        ("IBAN", "New account GB82 WEST 1234 5698 7654 32", "GB82 WEST 1234 5698 7654 32"),
        ("SNILS", "New SNILS 112-233-445 95", "112-233-445 95"),
        (
            "PASSPORT",
            "Новый паспорт: серия 4510, номер 123456",
            "4510, номер 123456",
        ),
        (
            "JWT",
            "New token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234567890",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234567890",
        ),
        (
            "IP_ADDRESS",
            "New address 2001:db8:85a3::8a2e:370:7334",
            "2001:db8:85a3::8a2e:370:7334",
        ),
    ],
)
def test_output_guard_redacts_new_terminal_sensitive_values(
    entity_type: str,
    provider_text: str,
    raw_sensitive_value: str,
) -> None:
    detector = _AnalyzeOnlyDetector(DetectorEnsemble(profile=DetectorProfile.STRICT))
    guarded = OutputPrivacyGuard(detector).process(
        {"choices": [{"message": {"content": provider_text}}]},
        [],
    )

    content = guarded["choices"][0]["message"]["content"]
    assert raw_sensitive_value not in content
    assert f"[REDACTED_PROVIDER_{entity_type}]" in content


def test_output_guard_restores_only_scoped_values_in_responses_function_arguments() -> None:
    token = "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"
    mapping = [MappingItem("EMAIL", "owner@example.com", token)]
    response = {
        "output": [
            {
                "type": "function_call",
                "name": "lookup_customer",
                "id": "item_fc_123",
                "call_id": "call_123",
                "arguments": (
                    '{"nested":{"'
                    + token
                    + '":"new@example.net",'
                    + '"billing":"GB82 WEST 1234 5698 7654 32"}}'
                ),
            }
        ],
        "id": "resp_123",
        "object": "response",
    }

    guarded = OutputPrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT)).process(
        response, mapping
    )

    item = guarded["output"][0]
    assert item["type"] == "function_call"
    assert item["id"] == "item_fc_123"
    assert item["call_id"] == "call_123"
    assert item["name"] == "lookup_customer"
    assert guarded["id"] == "resp_123"
    assert guarded["object"] == "response"
    assert "owner@example.com" in item["arguments"]
    assert "new@example.net" not in item["arguments"]
    assert "[REDACTED_PROVIDER_EMAIL]" in item["arguments"]
    assert "GB82 WEST 1234 5698 7654 32" not in item["arguments"]
    assert "[REDACTED_PROVIDER_IBAN]" in item["arguments"]


def test_unvalidated_output_does_not_trust_sensitive_protocol_shaped_fields() -> None:
    guarded = OutputPrivacyGuard(DetectorEnsemble(profile=DetectorProfile.STRICT)).process(
        {
            "id": "response@example.com",
            "object": "owner@example.com",
            "output": [
                {
                    "type": "function_call",
                    "id": "item@example.com",
                    "call_id": "call@example.com",
                    "name": "owner@example.com",
                    "arguments": "{}",
                }
            ],
        },
        [],
    )

    assert guarded["id"] == "[REDACTED_PROVIDER_EMAIL]"
    assert guarded["object"] == "[REDACTED_PROVIDER_EMAIL]"
    item = guarded["output"][0]
    assert item["id"] == "[REDACTED_PROVIDER_EMAIL]"
    assert item["call_id"] == "[REDACTED_PROVIDER_EMAIL]"
    assert item["name"] == "[REDACTED_PROVIDER_EMAIL]"
