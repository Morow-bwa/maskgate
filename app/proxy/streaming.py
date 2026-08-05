from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.masking.anonymizer import MappingItem
from app.masking.rehydrator import rehydrate_text


def extract_delta_text(event: dict[str, Any]) -> str:
    choices = event.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    choice = choices[0]
    if not isinstance(choice, dict):
        return ""
    delta = choice.get("delta")
    if isinstance(delta, dict) and isinstance(delta.get("content"), str):
        return delta["content"]
    return ""


def replace_delta_text(event: dict[str, Any], text: str) -> dict[str, Any]:
    updated = deepcopy(event)
    choices = updated.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return updated
    delta = choices[0].setdefault("delta", {})
    if isinstance(delta, dict):
        delta["content"] = text
    return updated


class StreamingRehydrator:
    """Rehydrate tokens without leaking a token split across stream chunks."""

    def __init__(self, mapping: list[MappingItem]) -> None:
        self.mapping = [item for item in mapping if item.restore]
        self.buffer = ""

    def push(self, text: str) -> str:
        self.buffer += text
        hold = self._partial_token_suffix()
        if hold:
            safe = self.buffer[:-len(hold)]
            self.buffer = hold
        else:
            safe = self.buffer
            self.buffer = ""
        return rehydrate_text(safe, self.mapping)

    def finish(self) -> str:
        final = rehydrate_text(self.buffer, self.mapping)
        self.buffer = ""
        return final

    def _partial_token_suffix(self) -> str:
        replacements = [item.replacement for item in self.mapping]
        if not replacements or "<" not in self.buffer:
            return ""
        start = self.buffer.rfind("<")
        candidate = self.buffer[start:]
        if any(token.startswith(candidate) and candidate != token for token in replacements):
            return candidate
        return ""
