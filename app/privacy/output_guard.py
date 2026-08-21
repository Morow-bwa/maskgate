from __future__ import annotations

import base64
import json
from typing import Any, Callable
from urllib.parse import unquote

from app.masking.anonymizer import MappingItem
from app.masking.rehydrator import rehydrate, rehydrate_text
from app.privacy.detection import PrivacyDetector
from app.privacy.models import DetectionContext, PrivacyDirection

from .wire import (
    BASE64_PATTERN,
    BASE64URL_PATTERN,
    HEX_PATTERN,
    MAX_ENCODED_TEXT_BYTES,
    OPAQUE_TOKEN_PATTERN,
    PERCENT_ESCAPE_PATTERN,
    UNICODE_ESCAPE_PATTERN,
)

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
        """Fail closed on sensitive or opaque encoded provider output.

        Provider output is untrusted. Encoded values cannot be restored safely
        by span, so the whole encoded field is redacted when a decoded view is
        sensitive. Member names keep the wire guard's narrower direct-check
        behavior to avoid interpreting ordinary protocol keys as Base64.
        """

        if path and path[-1] == "<key>":
            return text
        stripped = text.strip()
        if not stripped or len(stripped.encode("utf-8")) > MAX_ENCODED_TEXT_BYTES:
            return text

        if self._is_opaque_encoded_text(stripped):
            return "[REDACTED_PROVIDER_ENCODED]"

        decoded_views: list[str] = []
        if len(PERCENT_ESCAPE_PATTERN.findall(stripped)) >= 2:
            decoded_views.append(unquote(stripped))
        if UNICODE_ESCAPE_PATTERN.search(stripped):
            decoded_views.append(
                UNICODE_ESCAPE_PATTERN.sub(lambda match: chr(int(match.group(1), 16)), stripped)
            )
        if stripped[:1] in {"{", "["}:
            try:
                nested = json.loads(stripped)
            except json.JSONDecodeError:
                nested = None
            entity_type = self._first_unapproved_entity(
                nested,
                approved,
                (*path, "<encoded-json>"),
            )
            if entity_type is not None:
                return "[REDACTED_PROVIDER_ENCODED]"

        for decoded in decoded_views:
            if decoded == stripped:
                continue
            if OPAQUE_TOKEN_PATTERN.search(decoded):
                return "[REDACTED_PROVIDER_ENCODED_TOKEN]"
            entity_type = self._first_unapproved_entity(decoded, approved, path)
            if entity_type is not None:
                return "[REDACTED_PROVIDER_ENCODED]"
        return text

    @staticmethod
    def _is_opaque_encoded_text(text: str) -> bool:
        if HEX_PATTERN.fullmatch(text):
            return True
        if not (BASE64_PATTERN.fullmatch(text) or BASE64URL_PATTERN.fullmatch(text)):
            return False
        try:
            padded = text + "=" * (-len(text) % 4)
            if "-" in text or "_" in text:
                base64.urlsafe_b64decode(padded)
            else:
                base64.b64decode(padded, validate=False)
        except (ValueError, TypeError):
            return False
        return True

    def _first_unapproved_entity(
        self,
        value: Any,
        approved: set[str],
        path: tuple[str | int, ...],
        encoded_depth: int = 0,
    ) -> str | None:
        if isinstance(value, str):
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
            if encoded_depth >= 4:
                return None
            stripped = value.strip()
            if self._is_opaque_encoded_text(stripped):
                return "ENCODED"
            decoded_views: list[Any] = []
            if len(PERCENT_ESCAPE_PATTERN.findall(stripped)) >= 2:
                decoded_views.append(unquote(stripped))
            if UNICODE_ESCAPE_PATTERN.search(stripped):
                decoded_views.append(
                    UNICODE_ESCAPE_PATTERN.sub(
                        lambda match: chr(int(match.group(1), 16)),
                        stripped,
                    )
                )
            if stripped[:1] in {"{", "["}:
                try:
                    decoded_views.append(json.loads(stripped))
                except json.JSONDecodeError:
                    pass
            for decoded in decoded_views:
                if decoded == stripped:
                    continue
                entity_type = self._first_unapproved_entity(
                    decoded,
                    approved,
                    (*path, "<decoded>"),
                    encoded_depth + 1,
                )
                if entity_type is not None:
                    return entity_type
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
