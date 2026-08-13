from __future__ import annotations

from typing import Any, Callable

from app.masking.anonymizer import MappingItem
from app.masking.detector import RegexDetector
from app.masking.rehydrator import rehydrate, rehydrate_text

from .wire import OPAQUE_TOKEN_PATTERN

SAFE_PROTOCOL_LITERALS = frozenset(
    {
        "chat.completion",
        "chat.completion.chunk",
    }
)


class OutputPrivacyGuard:
    """Inspect untrusted provider output, then perform authorized restoration."""

    def __init__(self, detector: RegexDetector) -> None:
        self.detector = detector

    def process(self, value: Any, mapping: list[MappingItem]) -> Any:
        approved_replacements = {item.replacement for item in mapping if item.restore}
        sanitized = self._transform(
            value,
            lambda text: self._sanitize_provider_text(text, approved_replacements),
        )
        restored = self._restore_authorized(sanitized, mapping)
        restored = self._transform(
            restored,
            lambda text: self._redact_unrestored_tokens(text, approved_replacements),
        )
        approved_originals = {item.original for item in mapping if item.restore}
        return self._transform(
            restored,
            lambda text: self._sanitize_restored_text(text, approved_originals),
        )

    def sanitize_for_history(self, value: Any, mapping: list[MappingItem]) -> Any:
        """Sanitize provider output while retaining approved opaque tokens.

        Conversation history must remain provider-safe and must never contain
        rehydrated originals. It is inspected again on the next outbound turn.
        """
        approved_replacements = {item.replacement for item in mapping if item.restore}
        return self._transform(
            value,
            lambda text: self._sanitize_provider_text(text, approved_replacements),
        )

    def process_authorized_text(self, text: str, mapping: list[MappingItem]) -> str:
        approved_replacements = {item.replacement for item in mapping if item.restore}
        sanitized = self._sanitize_provider_text(text, approved_replacements)
        restored = rehydrate_text(sanitized, mapping)
        approved_originals = {item.original for item in mapping if item.restore}
        return self._sanitize_restored_text(restored, approved_originals)

    @staticmethod
    def _redact_unrestored_tokens(text: str, approved: set[str]) -> str:
        result = text
        for token in approved:
            result = result.replace(token, "[REDACTED_PROVIDER_TOKEN]")
        return result

    def _restore_authorized(
        self,
        value: Any,
        mapping: list[MappingItem],
        path: tuple[str | int, ...] = (),
    ) -> Any:
        if self._is_authorized_restore_path(path):
            return rehydrate(value, mapping)
        if isinstance(value, list):
            return [
                self._restore_authorized(item, mapping, (*path, index))
                for index, item in enumerate(value)
            ]
        if isinstance(value, dict):
            return {
                key: self._restore_authorized(item, mapping, (*path, key))
                for key, item in value.items()
            }
        return value

    @staticmethod
    def _is_authorized_restore_path(path: tuple[str | int, ...]) -> bool:
        keys = tuple(part for part in path if isinstance(part, str))
        return keys in {
            ("choices", "message", "content"),
            ("choices", "message", "function_call", "arguments"),
            ("choices", "message", "tool_calls", "function", "arguments"),
            ("output", "content", "text"),
            ("content", "text"),
        }

    def _sanitize_provider_text(self, text: str, approved: set[str]) -> str:
        result = text
        for token in OPAQUE_TOKEN_PATTERN.findall(text):
            if token not in approved:
                result = result.replace(token, "[REDACTED_PROVIDER_TOKEN]")
        return self._redact_detected(result, approved)

    def _sanitize_restored_text(self, text: str, approved: set[str]) -> str:
        return self._redact_detected(text, approved)

    def _redact_detected(self, text: str, approved: set[str]) -> str:
        if text in SAFE_PROTOCOL_LITERALS:
            return text
        replacements: list[tuple[int, int, str]] = []
        for entity in self.detector.detect(text):
            if entity.text not in approved:
                replacements.append(
                    (entity.start, entity.end, f"[REDACTED_PROVIDER_{entity.type}]")
                )
        result = text
        for start, end, replacement in reversed(replacements):
            result = result[:start] + replacement + result[end:]
        return result

    def _transform(self, value: Any, transform_text: Callable[[str], str]) -> Any:
        if isinstance(value, str):
            return transform_text(value)
        if isinstance(value, list):
            return [self._transform(item, transform_text) for item in value]
        if isinstance(value, dict):
            transformed: dict[Any, Any] = {}
            for key, item in value.items():
                updated_key = transform_text(key) if isinstance(key, str) else key
                if updated_key in transformed:
                    raise ValueError("output privacy transformation produced a duplicate key")
                transformed[updated_key] = self._transform(item, transform_text)
            return transformed
        return value
