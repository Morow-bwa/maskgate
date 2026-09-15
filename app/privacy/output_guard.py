from __future__ import annotations

from typing import Any, Callable

from app.masking.anonymizer import MappingItem
from app.masking.rehydrator import rehydrate, rehydrate_text
from app.privacy.detection import PrivacyDetector
from app.privacy.models import DetectionContext, PrivacyDirection

from .encoded import (
    MAX_ENCODED_TEXT_BYTES,
    SCHEMA_KEYS,
    EncodedContentViolation,
    decoded_views,
    is_protocol_id,
)
from .wire import OPAQUE_TOKEN_PATTERN

SAFE_PROTOCOL_LITERALS = frozenset(
    {
        "chat.completion",
        "chat.completion.chunk",
    }
)


class OutputPrivacyGuard:
    """Inspect untrusted provider output, then perform authorized restoration."""

    def __init__(self, detector: PrivacyDetector) -> None:
        self.detector = detector

    def process(self, value: Any, mapping: list[MappingItem]) -> Any:
        approved_replacements = {item.replacement for item in mapping if item.restore}
        sanitized = self._transform(
            value,
            lambda text, path: self._sanitize_provider_text(text, approved_replacements, path),
        )
        restored = self._restore_authorized(sanitized, mapping)
        restored = self._transform(
            restored,
            lambda text, _path: self._redact_unrestored_tokens(text, approved_replacements),
        )
        approved_originals = {item.original for item in mapping if item.restore}
        return self._transform(
            restored,
            lambda text, path: self._sanitize_restored_text(text, approved_originals, path),
        )

    def sanitize_for_history(self, value: Any, mapping: list[MappingItem]) -> Any:
        """Sanitize provider output while retaining approved opaque tokens.

        Conversation history must remain provider-safe and must never contain
        rehydrated originals. It is inspected again on the next outbound turn.
        """
        approved_replacements = {item.replacement for item in mapping if item.restore}
        return self._transform(
            value,
            lambda text, path: self._sanitize_provider_text(text, approved_replacements, path),
        )

    def process_authorized_text(self, text: str, mapping: list[MappingItem]) -> str:
        approved_replacements = {item.replacement for item in mapping if item.restore}
        sanitized = self._sanitize_provider_text(text, approved_replacements, ())
        restored = rehydrate_text(sanitized, mapping)
        approved_originals = {item.original for item in mapping if item.restore}
        return self._sanitize_restored_text(restored, approved_originals, ())

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
            ("output", "arguments"),
            ("content", "text"),
        }

    def _sanitize_provider_text(
        self,
        text: str,
        approved: set[str],
        path: tuple[str | int, ...],
    ) -> str:
        if len(text.encode("utf-8")) > MAX_ENCODED_TEXT_BYTES:
            return "[REDACTED_PROVIDER_ENCODED]"
        result = text
        for token in OPAQUE_TOKEN_PATTERN.findall(text):
            if token not in approved:
                result = result.replace(token, "[REDACTED_PROVIDER_TOKEN]")
        result = self._redact_detected(result, approved, path)
        return self._redact_encoded(result, approved, path)

    def _sanitize_restored_text(
        self,
        text: str,
        approved: set[str],
        path: tuple[str | int, ...],
    ) -> str:
        return self._redact_detected(text, approved, path)

    def _redact_detected(
        self,
        text: str,
        approved: set[str],
        path: tuple[str | int, ...],
    ) -> str:
        if text in SAFE_PROTOCOL_LITERALS:
            return text
        replacements: list[tuple[int, int, str]] = []
        for detection in self.detector.analyze(
            text,
            DetectionContext(
                profile=self.detector.profile,
                json_path=path,
                direction=PrivacyDirection.OUTPUT,
            ),
        ):
            detected_value = text[detection.start : detection.end]
            if detected_value not in approved:
                replacements.append(
                    (
                        detection.start,
                        detection.end,
                        f"[REDACTED_PROVIDER_{detection.entity_type}]",
                    )
                )
        result = text
        for start, end, replacement in reversed(replacements):
            result = result[:start] + replacement + result[end:]
        return result

    def _redact_encoded(
        self,
        text: str,
        approved: set[str],
        path: tuple[str | int, ...],
    ) -> str:
        """Inspect keys and values using the same bounded views as the wire guard."""
        candidate = text
        for token in approved:
            candidate = candidate.replace(token, "")
        protocol = (path and path[-1] == "<key>" and text in SCHEMA_KEYS) or is_protocol_id(
            text, path, output=True
        )
        try:
            for decoded in decoded_views(candidate, protocol=bool(protocol)):
                if self._first_unapproved_entity(decoded, approved, (*path, "<decoded>"), 1):
                    return "[REDACTED_PROVIDER_ENCODED]"
        except (EncodedContentViolation, UnicodeError):
            return "[REDACTED_PROVIDER_ENCODED]"
        return text

    def _first_unapproved_entity(
        self,
        value: Any,
        approved: set[str],
        path: tuple[str | int, ...],
        encoded_depth: int = 0,
    ) -> str | None:
        if isinstance(value, str):
            if len(value.encode("utf-8")) > MAX_ENCODED_TEXT_BYTES:
                return "ENCODED"
            if any(token not in approved for token in OPAQUE_TOKEN_PATTERN.findall(value)):
                return "TOKEN"
            for detection in self.detector.analyze(
                value,
                DetectionContext(
                    profile=self.detector.profile,
                    json_path=path,
                    direction=PrivacyDirection.OUTPUT,
                ),
            ):
                detected_value = value[detection.start : detection.end]
                if detected_value not in approved:
                    return detection.entity_type
            candidate = value
            for token in approved:
                candidate = candidate.replace(token, "")
            try:
                views = decoded_views(candidate, depth=encoded_depth)
                for decoded in views:
                    entity_type = self._first_unapproved_entity(
                        decoded,
                        approved,
                        (*path, "<decoded>"),
                        encoded_depth + 1,
                    )
                    if entity_type is not None:
                        return entity_type
            except (EncodedContentViolation, UnicodeError):
                return "ENCODED"
            return None
        if isinstance(value, list):
            for index, item in enumerate(value):
                entity_type = self._first_unapproved_entity(
                    item,
                    approved,
                    (*path, index),
                    encoded_depth,
                )
                if entity_type is not None:
                    return entity_type
            return None
        if isinstance(value, dict):
            for key, item in value.items():
                entity_type = self._first_unapproved_entity(
                    str(key),
                    approved,
                    (*path, "<key>"),
                    encoded_depth,
                )
                if entity_type is None:
                    entity_type = self._first_unapproved_entity(
                        item,
                        approved,
                        (*path, str(key)),
                        encoded_depth,
                    )
                if entity_type is not None:
                    return entity_type
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return "NUMERIC"
        return None

    def _transform(
        self,
        value: Any,
        transform_text: Callable[[str, tuple[str | int, ...]], str],
        path: tuple[str | int, ...] = (),
    ) -> Any:
        if isinstance(value, str):
            return transform_text(value, path)
        if isinstance(value, list):
            return [
                self._transform(item, transform_text, (*path, index))
                for index, item in enumerate(value)
            ]
        if isinstance(value, dict):
            transformed: dict[Any, Any] = {}
            for key, item in value.items():
                updated_key = transform_text(key, (*path, "<key>")) if isinstance(key, str) else key
                if updated_key in transformed:
                    raise ValueError("output privacy transformation produced a duplicate key")
                transformed[updated_key] = self._transform(
                    item,
                    transform_text,
                    (*path, key),
                )
            return transformed
        return value
