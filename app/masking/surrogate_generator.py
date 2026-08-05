from __future__ import annotations

from collections import defaultdict


class SurrogateGenerator:
    """Generate deterministic, obviously synthetic values for one request."""

    def __init__(self) -> None:
        self._counters: defaultdict[str, int] = defaultdict(int)

    def generate(self, entity_type: str) -> str:
        self._counters[entity_type] += 1
        index = self._counters[entity_type]
        values = {
            "PERSON": ["Demo Person One", "Demo Person Two", "Demo Person Three"],
            "ORG": ["Northwind Labs", "Example Systems", "Contoso Research"],
            "EMAIL": ["demo.one@example.test", "demo.two@example.test"],
            "PHONE": ["+1 202-555-0101", "+1 202-555-0102"],
            "IP_ADDRESS": ["198.51.100.10", "203.0.113.10"],
            "DOMAIN": ["example.test", "internal.example.test"],
            "URL": ["https://example.test/resource", "https://internal.example.test/item"],
            "API_KEY": ["sk-test-maskgate-000000000001", "sk-test-maskgate-000000000002"],
            "FILE_PATH": [r"C:\Users\Demo\Documents\file.txt", r"/home/demo/documents/file.txt"],
            "MONEY": ["$1,234.56", "$987.65"],
            "CARD_NUMBER": ["4111 1111 1111 1111", "5555 5555 5555 4444"],
            "BANK": ["Example Bank", "Northwind Bank"],
            "LOCATION": ["Example City", "Northwind Avenue"],
        }
        choices = values.get(entity_type, [f"Synthetic {entity_type.title()} {index}"])
        return choices[(index - 1) % len(choices)]
