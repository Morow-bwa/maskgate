from app.masking.detector import Entity, RegexDetector, resolve_overlaps


def test_required_regex_entities_are_detected() -> None:
    text = (
        "Contact user@example.com or +1 202-555-0101 from 192.0.2.10. "
        "See https://internal.example.com/docs, key sk-test-abcdefghijklmnop, "
        "path C:\\Users\\Demo\\secret.txt, and pay $1,234.56."
    )
    entities = RegexDetector().detect(text)
    types = {entity.type for entity in entities}
    assert {"EMAIL", "PHONE", "IP_ADDRESS", "URL", "API_KEY", "FILE_PATH", "MONEY"} <= types


def test_domain_is_not_returned_inside_url() -> None:
    entities = RegexDetector().detect("https://internal.company.com/path")
    assert [entity.type for entity in entities] == ["URL"]


def test_domain_is_detected_before_sentence_punctuation() -> None:
    entities = RegexDetector().detect("Запрос ушел на api.internal.example.test.")
    assert [(item.type, item.text) for item in entities] == [
        ("DOMAIN", "api.internal.example.test")
    ]


def test_overlap_resolution_prefers_priority_then_longer_match() -> None:
    candidates = [
        Entity("DOMAIN", "company.com", 8, 19),
        Entity("URL", "https://company.com", 0, 19),
    ]
    assert resolve_overlaps(candidates)[0].type == "URL"


def test_card_number_is_detected() -> None:
    entities = RegexDetector().detect("Card 4111 1111 1111 1111")
    assert [(item.type, item.text) for item in entities] == [("CARD_NUMBER", "4111 1111 1111 1111")]


def test_card_number_does_not_consume_following_space() -> None:
    entities = RegexDetector().detect("Карта 4111 1111 1111 1111 и заявка CASE-10001")
    card = next(item for item in entities if item.type == "CARD_NUMBER")
    assert card.text == "4111 1111 1111 1111"


def test_inn_is_detected_by_its_label() -> None:
    entities = RegexDetector().detect("Ее ИНН 123456789012 указан в заявке")
    assert [(item.type, item.text) for item in entities] == [("INN", "123456789012")]


def test_russian_money_word_is_detected() -> None:
    entities = RegexDetector().detect("Она перевела 5000 долларов на счет")
    assert [(item.type, item.text) for item in entities] == [("MONEY", "5000 долларов")]


def test_conservative_person_pattern_detects_two_cyrillic_name_tokens() -> None:
    entities = RegexDetector().detect("Автор Лев Толстой")
    assert [(item.type, item.text) for item in entities] == [("PERSON", "Лев Толстой")]


def test_person_detector_does_not_mask_normal_sentence_fragments() -> None:
    text = (
        "Здравствуйте. Меня зовут Алекс Тестов, я представляю ООО «Пример». "
        "Пожалуйста, подготовьте ответ клиенту Мария Примерова, которая написала нам "
        "с почты customer@example.org и попросила перезвонить ей по номеру +1 202-555-0101. "
        "Клиент сообщает, что перевел 5000 долларов на счет в Example Bank. "
        "Наш технический специалист Олег Синтетиков проверил лог-файл. "
        "Составь вежливый ответ клиентке."
    )
    entities = RegexDetector().detect(text)
    person_matches = [item.text for item in entities if item.type == "PERSON"]
    assert person_matches == ["Алекс Тестов", "Мария Примерова", "Олег Синтетиков"]
