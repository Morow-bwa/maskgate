from app.masking.detector import RegexDetector


def test_email_before_sentence_punctuation_is_detected() -> None:
    entities = RegexDetector().detect("Reply to billing@example.org.")

    assert [(item.type, item.text) for item in entities] == [("EMAIL", "billing@example.org")]
