from app.masking.anonymizer import MappingItem
from app.masking.rehydrator import rehydrate, rehydrate_text


def test_rehydrate_text_and_nested_payload() -> None:
    mapping = [MappingItem("EMAIL", "user@example.com", "<EMAIL_1>")]
    assert rehydrate_text("Hello <EMAIL_1>", mapping) == "Hello user@example.com"
    assert rehydrate({"choices": [{"message": {"content": "<EMAIL_1>"}}]}, mapping) == {
        "choices": [{"message": {"content": "user@example.com"}}]
    }
