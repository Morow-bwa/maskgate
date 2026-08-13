from __future__ import annotations

from typing import Any

from .anonymizer import MappingItem


def rehydrate_text(text: str, mapping: list[MappingItem]) -> str:
    result = text
    # Longest first prevents a shorter token from changing a longer one.
    for item in sorted(
        (entry for entry in mapping if entry.restore),
        key=lambda entry: len(entry.replacement),
        reverse=True,
    ):
        result = result.replace(item.replacement, item.original)
    return result


def rehydrate(value: Any, mapping: list[MappingItem]) -> Any:
    if isinstance(value, str):
        return rehydrate_text(value, mapping)
    if isinstance(value, list):
        return [rehydrate(item, mapping) for item in value]
    if isinstance(value, dict):
        restored: dict[Any, Any] = {}
        for key, item in value.items():
            restored_key = rehydrate_text(key, mapping) if isinstance(key, str) else key
            if restored_key in restored:
                raise ValueError("rehydration produced a duplicate dictionary key")
            restored[restored_key] = rehydrate(item, mapping)
        return restored
    return value
