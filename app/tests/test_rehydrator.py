from app.masking.anonymizer import MappingItem
from app.masking.rehydrator import rehydrate, rehydrate_text


def test_rehydrate_text_and_nested_payload() -> None:
    mapping = [MappingItem("EMAIL", "user@example.com", "<EMAIL_1>")]
    assert rehydrate_text("Hello <EMAIL_1>", mapping) == "Hello user@example.com"
    assert rehydrate({"choices": [{"message": {"content": "<EMAIL_1>"}}]}, mapping) == {
        "choices": [{"message": {"content": "user@example.com"}}]
    }


def test_rehydration_ignores_fake_modified_partial_and_foreign_tokens() -> None:
    active = "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAA>"
    foreign = "<MG:BBBBBBBBBBBBBBBBBBBBBBBBBB>"
    mapping = [MappingItem("EMAIL", "owner@example.com", active)]
    modified = "<MG:AAAAAAAAAAAAAAAAAAAAAAAAAB>"
    partial = active[:-1]

    restored = rehydrate_text(
        f"active={active}; duplicate={active}; foreign={foreign}; "
        f"modified={modified}; partial={partial}",
        mapping,
    )

    assert restored.count("owner@example.com") == 2
    assert foreign in restored
    assert modified in restored
    assert partial in restored
