from __future__ import annotations

from collections import defaultdict


class SurrogateGenerator:
    """Generate deterministic, obviously synthetic values for one request."""

    def __init__(self) -> None:
        self._counters: defaultdict[str, int] = defaultdict(int)

    def generate(self, entity_type: str) -> str:
        self._counters[entity_type] += 1
        index = self._counters[entity_type]
        generators = {
            "PERSON": lambda value: f"Demo Person {value}",
            "ORG": lambda value: f"Example Organization {value}",
            "EMAIL": lambda value: f"demo.{value}@example.test",
            "PHONE": lambda value: f"+1 202-555-{value % 10_000:04d} ext {value}",
            "IP_ADDRESS": lambda value: f"198.51.{(value // 254) % 254}.{value % 254 + 1}",
            "DOMAIN": lambda value: f"demo-{value}.example.test",
            "URL": lambda value: f"https://example.test/resource/{value}",
            "API_KEY": lambda value: f"sk-test-maskgate-{value:024d}",
            "FILE_PATH": lambda value: rf"C:\MaskGate\Synthetic\file-{value}.txt",
            "MONEY": lambda value: f"${value:,}.00",
            "CARD_NUMBER": lambda value: f"0000 0000 {value // 10_000:04d} {value % 10_000:04d}",
            "BANK": lambda value: f"Example Bank {value}",
            "LOCATION": lambda value: f"Example Location {value}",
        }
        generator = generators.get(
            entity_type,
            lambda value: f"Synthetic {entity_type.title()} {value}",
        )
        return generator(index)
