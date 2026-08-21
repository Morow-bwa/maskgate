from app.privacy.detection import DetectorEnsemble, LegacyEntityDetectorAdapter
from app.privacy.models import DetectorProfile


def test_runtime_adapter_preserves_original_span_after_unicode_canonicalization() -> None:
    adapter = LegacyEntityDetectorAdapter(DetectorEnsemble(profile=DetectorProfile.STRICT))
    text = "Mail: user\u200b@example.com"

    entities = adapter.detect(text)
    email = next(item for item in entities if item.type == "EMAIL")

    assert email.text == "user\u200b@example.com"
    assert text[email.start : email.end] == email.text
    assert email.method


def test_runtime_adapter_exposes_v2_detection_metadata() -> None:
    adapter = LegacyEntityDetectorAdapter(DetectorEnsemble(profile=DetectorProfile.STRICT))

    detection = next(
        item for item in adapter.analyze("Contact user@example.com") if item.entity_type == "EMAIL"
    )

    assert detection.data_class.value == "DIRECT_PII"
    assert detection.confidence >= 0.9
