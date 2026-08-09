from app.masking.anonymizer import MaskingSession
from app.masking.detector import RegexDetector
from app.masking.rehydrator import rehydrate_text
from app.policies.policy_engine import PolicyEngine


def test_placeholder_anonymization_is_consistent(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("placeholder", policy)
    detector = RegexDetector()
    first = session.mask_text("Email user@example.com", detector.detect("Email user@example.com"))
    second = session.mask_text("Again user@example.com", detector.detect("Again user@example.com"))
    token = session.items[0].replacement
    assert first == f"Email {token}"
    assert second == f"Again {token}"
    assert len(session.items) == 1


def test_surrogate_anonymization_uses_synthetic_values(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("surrogate", policy)
    text = "Email user@example.com"
    masked = session.mask_text(text, RegexDetector().detect(text))
    assert masked.endswith("@example.test")
    assert "user@example.com" not in masked


def test_redact_mode_is_not_rehydrated(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("redact", policy)
    text = "Email user@example.com"
    masked = session.mask_text(text, RegexDetector().detect(text))
    assert masked == "Email [REDACTED_EMAIL]"
    assert session.items[0].restore is False


def test_same_value_reuses_token_across_detected_entity_types(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("placeholder", policy)
    detector = RegexDetector()
    first = detector.detect("user@example.com")[0]
    second = detector.detect("user@example.com")[0]
    second = type(second)("DOMAIN", second.text, second.start, second.end)

    first_masked = session.mask_text(first.text, [first])
    assert session.mask_text(second.text, [second]) == first_masked
    assert len(session.items) == 1


def test_placeholder_namespace_prevents_literal_token_collisions(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    session = MaskingSession("placeholder", policy)
    detector = RegexDetector()
    text = "Keep literal <EMAIL_1>; contact collision.user@example.com"

    masked = session.mask_text(text, detector.detect(text))
    token = session.items[0].replacement

    assert token.startswith("<MG_")
    assert token != "<EMAIL_1>"
    assert "<EMAIL_1>" in masked
    assert rehydrate_text(f"Literal <EMAIL_1>; contact {token}", session.items) == (
        "Literal <EMAIL_1>; contact collision.user@example.com"
    )


def test_allowlisted_public_email_is_left_visible(settings) -> None:
    policy = PolicyEngine(settings.policy_file, public_email_allowlist=("info@example.com",))
    session = MaskingSession("placeholder", policy)
    text = "Public mailbox info@example.com"

    assert session.mask_text(text, RegexDetector().detect(text)) == text
    assert session.items == []


def test_unknown_person_is_masked_but_allowlisted_public_person_is_not(settings) -> None:
    policy = PolicyEngine(settings.policy_file, public_person_allowlist=("Лев Толстой",))
    detector = RegexDetector()

    public_text = "Автор Лев Толстой"
    private_text = "Контакт Тестовый Пользователь"
    public_session = MaskingSession("placeholder", policy)
    private_session = MaskingSession("placeholder", policy)

    assert public_session.mask_text(public_text, detector.detect(public_text)) == public_text
    assert (
        private_session.mask_text(private_text, detector.detect(private_text))
        == f"Контакт {private_session.items[0].replacement}"
    )
