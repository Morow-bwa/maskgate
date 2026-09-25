from __future__ import annotations

import pytest

from app.privacy.detection import CanonicalText, DetectorEnsemble
from app.privacy.detection.canonical import CanonicalizationError
from app.privacy.detection.validators import (
    is_valid_iban,
    is_valid_inn,
    is_valid_luhn,
    is_valid_snils,
)
from app.privacy.models import DataClass, DetectionContext, DetectorProfile, ValidationState


def test_canonical_text_detects_nfkc_and_zero_width_text_with_original_span() -> None:
    source = "Contact ａｌｉｃｅ\u200b＠ｅｘａｍｐｌｅ．ｃｏｍ"

    canonical = CanonicalText.from_text(source)
    start = canonical.text.index("alice@example.com")
    end = start + len("alice@example.com")

    assert canonical.text == "Contact alice@example.com"
    assert source[slice(*canonical.original_span(start, end))] == (
        "ａｌｉｃｅ\u200b＠ｅｘａｍｐｌｅ．ｃｏｍ"
    )


def test_checksum_validators_reject_near_miss_identifiers() -> None:
    assert is_valid_luhn("4111 1111 1111 1111")
    assert not is_valid_luhn("4111 1111 1111 1112")
    assert is_valid_inn("7707083893")
    assert is_valid_inn("500100732259")
    assert not is_valid_inn("7707083894")
    assert is_valid_snils("112-233-445 95")
    assert not is_valid_snils("112-233-445 96")
    assert is_valid_iban("GB82 WEST 1234 5698 7654 32")
    assert not is_valid_iban("GB82 WEST 1234 5698 7654 33")


def test_canonicalization_is_bounded_and_preserves_combining_provenance() -> None:
    source = "A\u00a0Cafe\u0301\u200b"
    canonical = CanonicalText.from_text(source)

    assert canonical.text == "A Café"
    accent = canonical.text.index("é")
    assert canonical.original_text(accent, accent + 1) == "e\u0301"
    with pytest.raises(CanonicalizationError, match="input exceeds"):
        CanonicalText.from_text("abcd", max_input_chars=3)


def test_ensemble_reports_canonicalized_email_at_original_span() -> None:
    source = "Contact ａｌｉｃｅ\u200b＠ｅｘａｍｐｌｅ．ｃｏｍ"

    detections = DetectorEnsemble().detect(
        source,
        DetectionContext(locale="en-US", profile=DetectorProfile.BALANCED),
    )

    assert len(detections) == 1
    detection = detections[0]
    assert detection.entity_type == "EMAIL"
    assert detection.data_class is DataClass.DIRECT_PII
    assert detection.validation_state is ValidationState.VALID
    assert source[detection.start : detection.end] == "ａｌｉｃｅ\u200b＠ｅｘａｍｐｌｅ．ｃｏｍ"


def test_ensemble_detects_structured_auth_secrets_without_remote_ml() -> None:
    private_key_header = "-----BEGIN " + "PRIVATE KEY-----"
    text = (
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "signature1234567890; database postgresql://app:s3cret@db.example.test/customer; "
        f"key {private_key_header}"
    )

    detections = DetectorEnsemble().detect(text)

    assert {item.entity_type for item in detections} == {
        "JWT",
        "CONNECTION_STRING",
        "PRIVATE_KEY",
    }
    assert all(item.data_class is DataClass.AUTH_SECRET for item in detections)
    assert all(item.validation_state is ValidationState.VALID for item in detections)


def test_ensemble_validates_ipv6_as_a_quasi_identifier() -> None:
    text = "Observed source [2001:db8:85a3::8a2e:370:7334] during login"

    detections = DetectorEnsemble().detect(text)

    assert len(detections) == 1
    detection = detections[0]
    assert detection.entity_type == "IP_ADDRESS"
    assert detection.data_class is DataClass.QUASI_IDENTIFIER
    assert detection.validation_state is ValidationState.VALID
    assert text[detection.start : detection.end] == "2001:db8:85a3::8a2e:370:7334"


def test_ru_identity_recognizer_validates_checksums_and_passport_context() -> None:
    text = "ИНН 7707083893; СНИЛС 112-233-445 95; паспорт: серия 4510, номер 123456"

    detections = DetectorEnsemble().detect(
        text,
        DetectionContext(locale="ru-RU", profile=DetectorProfile.BALANCED),
    )
    by_type = {item.entity_type: item for item in detections}

    assert set(by_type) == {"INN", "SNILS", "PASSPORT"}
    assert by_type["INN"].validation_state is ValidationState.VALID
    assert by_type["SNILS"].validation_state is ValidationState.VALID
    assert by_type["PASSPORT"].validation_state is ValidationState.UNVALIDATED
    assert by_type["PASSPORT"].context_score > 0
    assert text[by_type["PASSPORT"].start : by_type["PASSPORT"].end] == "4510, номер 123456"


def test_ensemble_detects_only_checksum_valid_iban_candidates() -> None:
    text = "Valid GB82 WEST 1234 5698 7654 32; invalid GB82 WEST 1234 5698 7654 33"

    detections = DetectorEnsemble().detect(text)

    iban_detections = [item for item in detections if item.entity_type == "IBAN"]
    assert len(iban_detections) == 1
    assert text[iban_detections[0].start : iban_detections[0].end] == (
        "GB82 WEST 1234 5698 7654 32"
    )
    assert iban_detections[0].data_class is DataClass.FINANCIAL


def test_profiles_make_ambiguous_ru_passport_detection_explicit() -> None:
    text = "Record 4510 123456 is awaiting manual classification"

    balanced = DetectorEnsemble(profile=DetectorProfile.BALANCED).detect(text)
    strict = DetectorEnsemble(profile=DetectorProfile.STRICT).detect(text)

    assert all(item.entity_type != "PASSPORT" for item in balanced)
    passport = next(item for item in strict if item.entity_type == "PASSPORT")
    assert passport.validation_state is ValidationState.AMBIGUOUS
    assert passport.confidence < 0.65


def test_balanced_profile_rejects_failed_checksums_but_strict_marks_them_invalid() -> None:
    text = "ИНН 7707083894; card 4111 1111 1111 1112"

    balanced = DetectorEnsemble(profile=DetectorProfile.BALANCED).detect(text)
    strict = DetectorEnsemble(profile=DetectorProfile.STRICT).detect(text)

    assert not {"INN", "CARD_NUMBER"} & {item.entity_type for item in balanced}
    invalid = {
        item.entity_type: item.validation_state
        for item in strict
        if item.entity_type in {"INN", "CARD_NUMBER"}
    }
    assert invalid == {
        "INN": ValidationState.INVALID,
        "CARD_NUMBER": ValidationState.INVALID,
    }
