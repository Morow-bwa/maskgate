from __future__ import annotations

from app.privacy.detection import DetectorEnsemble
from app.privacy.detection.recognizers.contextual import LocalizedContextRecognizer
from app.privacy.models import DataClass, DetectionContext, DetectorProfile


def _detect(text: str, locale: str):
    detector = DetectorEnsemble(
        recognizers=(LocalizedContextRecognizer(),),
        profile=DetectorProfile.BALANCED,
    )
    return detector.detect(
        text,
        DetectionContext(locale=locale, profile=DetectorProfile.BALANCED),
    )


def test_labeled_russian_person_is_detected_without_remote_inference() -> None:
    text = "Контактное лицо: Анна Кузнецова подтвердила заявку."

    detections = _detect(text, "ru-RU")

    assert len(detections) == 1
    person = detections[0]
    assert person.entity_type == "PERSON"
    assert person.data_class is DataClass.DIRECT_PII
    assert person.recognizer == "localized-context"
    assert text[person.start : person.end] == "Анна Кузнецова"


def test_english_organization_and_location_use_distinct_data_classes() -> None:
    text = "Alice Johnson joined Northwind Analytics Ltd in London."

    detections = _detect(text, "en-GB")
    by_type = {item.entity_type: item for item in detections}

    assert set(by_type) == {"PERSON", "ORG", "LOCATION"}
    assert text[by_type["PERSON"].start : by_type["PERSON"].end] == "Alice Johnson"
    assert text[by_type["ORG"].start : by_type["ORG"].end] == "Northwind Analytics Ltd"
    assert by_type["ORG"].data_class is DataClass.BUSINESS_CONFIDENTIAL
    assert text[by_type["LOCATION"].start : by_type["LOCATION"].end] == "London"
    assert by_type["LOCATION"].data_class is DataClass.LOCATION


def test_ukrainian_address_and_date_of_birth_are_structurally_validated() -> None:
    text = "Адреса: вулиця Лесі Українки, буд. 17, кв. 4; дата народження: 29 лютого 1988."

    detections = _detect(text, "uk-UA")
    by_type = {item.entity_type: item for item in detections}

    assert set(by_type) == {"POSTAL_ADDRESS", "DOB"}
    assert text[by_type["POSTAL_ADDRESS"].start : by_type["POSTAL_ADDRESS"].end] == (
        "вулиця Лесі Українки, буд. 17, кв. 4"
    )
    assert by_type["POSTAL_ADDRESS"].data_class is DataClass.LOCATION
    assert text[by_type["DOB"].start : by_type["DOB"].end] == "29 лютого 1988"
    assert by_type["DOB"].validation_state.value == "VALID"


def test_impossible_date_is_not_promoted_to_dob() -> None:
    detections = _detect("Date of birth: 31 February 2001.", "en-GB")

    assert all(item.entity_type != "DOB" for item in detections)


def test_unlabeled_numeric_identifiers_are_not_promoted_to_phone() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)

    detections = detector.detect("Order 1234567890 and build 202608131234 are identifiers.")

    assert all(item.entity_type != "PHONE" for item in detections)


def test_international_phone_remains_detectable_after_identifier_filtering() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)

    detections = detector.detect("Call +1 415 555 2671 or +7 916 123-45-67.")

    assert [item.entity_type for item in detections] == ["PHONE", "PHONE"]


def test_dotted_encoded_labels_are_not_promoted_to_domain() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)

    detections = detector.detect(
        "The invalid token aaaaaaaa.bbbbbbbb.signature differs from api.internal.example.test."
    )

    domains = [item for item in detections if item.entity_type == "DOMAIN"]
    assert len(domains) == 1
    assert domains[0].entity_type == "DOMAIN"
    assert (
        "The invalid token aaaaaaaa.bbbbbbbb.signature differs from api.internal.example.test."
    )[domains[0].start : domains[0].end] == "api.internal.example.test"


def test_explicit_document_and_project_titles_are_not_promoted_to_person() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
    text = (
        "Фраза Новая Политика является заголовком документа. "
        "Северный Ветер без правовой формы является названием проекта."
    )

    detections = detector.detect(text, DetectionContext(locale="ru-RU"))

    assert all(item.entity_type != "PERSON" for item in detections)


def test_invalid_iban_is_not_misclassified_as_payment_card() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)

    detections = detector.detect("Invalid IBAN GB82 WEST 1234 5698 7654 33.")

    assert all(item.entity_type != "CARD_NUMBER" for item in detections)


def test_english_currency_word_is_money_not_phone() -> None:
    detector = DetectorEnsemble(profile=DetectorProfile.STRICT)
    text = "The invoice total is 5000 dollars; order 50001234 is unchanged."

    detections = detector.detect(text, DetectionContext(locale="en-US"))

    money = [item for item in detections if item.entity_type == "MONEY"]
    assert len(money) == 1
    assert text[money[0].start : money[0].end] == "5000 dollars"
    assert all(item.entity_type != "PHONE" for item in detections)
