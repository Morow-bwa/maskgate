from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from app.policies.policy_engine import PolicyBlocked

PathPart = str | int
MaskText = Callable[[str], str]
MaskTextAtPath = Callable[[str, tuple[PathPart, ...]], str]
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


class UnsafeProtocolString(PolicyBlocked):
    """A schema identifier contains PII or cannot be sent without mutation."""

    def __init__(self, path: tuple[PathPart, ...]) -> None:
        self.path = path
        super().__init__(["PROTOCOL_FIELD"])


def sanitize_outbound_payload(
    payload: dict[str, Any],
    mask_text: MaskText,
    *,
    validate_protocol: bool = True,
    mask_text_at_path: MaskTextAtPath | None = None,
) -> dict[str, Any]:
    """Return a recursively sanitized copy of an OpenAI-compatible payload.

    Every string is treated as user-controlled text unless its path is a known
    protocol identifier. Unknown extension fields are therefore sanitized by
    default instead of passing through untouched.
    """
    sanitized = _sanitize_value(
        payload,
        mask_text,
        (),
        validate_protocol,
        mask_text_at_path,
    )
    if not isinstance(sanitized, dict):  # Defensive invariant for type checkers and callers.
        raise TypeError("outbound payload must be an object")
    return sanitized


def _sanitize_value(
    value: Any,
    mask_text: MaskText,
    path: tuple[PathPart, ...],
    validate_protocol: bool,
    mask_text_at_path: MaskTextAtPath | None,
) -> Any:
    transform = (
        (lambda text: mask_text_at_path(text, path)) if mask_text_at_path is not None else mask_text
    )
    if isinstance(value, str):
        if _is_protocol_string(path):
            masked_value = transform(value)
            if not validate_protocol:
                return masked_value
            if masked_value != value or not _is_valid_protocol_string(path, value):
                raise UnsafeProtocolString(path)
            return value
        return transform(value)
    if isinstance(value, list):
        return [
            _sanitize_value(
                item,
                mask_text,
                (*path, index),
                validate_protocol,
                mask_text_at_path,
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        sanitized_dict: dict[Any, Any] = {}
        for key, item in value.items():
            sanitized_key = (
                mask_text_at_path(key, (*path, "<key>"))
                if isinstance(key, str) and mask_text_at_path is not None
                else mask_text(key)
                if isinstance(key, str)
                else key
            )
            if sanitized_key in sanitized_dict:
                # Irreversible redaction can map distinct sensitive keys to the
                # same value. Preserve both without exposing either original.
                suffix = 2
                base_key = str(sanitized_key)
                while f"{base_key}__MGKEY_{suffix}" in sanitized_dict:
                    suffix += 1
                sanitized_key = f"{base_key}__MGKEY_{suffix}"
            sanitized_dict[sanitized_key] = _sanitize_value(
                item,
                mask_text,
                (*path, key),
                validate_protocol,
                mask_text_at_path,
            )
        return sanitized_dict
    return value


def _is_protocol_string(path: tuple[PathPart, ...]) -> bool:
    keys = tuple(part for part in path if isinstance(part, str))
    if keys == ("model",):
        return True

    exact_paths = {
        ("modalities",),
        ("reasoning_effort",),
        ("service_tier",),
        ("audio", "format"),
        ("audio", "voice"),
        ("response_format", "type"),
        ("messages", "role"),
        ("messages", "tool_call_id"),
        ("messages", "content", "type"),
        ("messages", "tool_calls", "id"),
        ("messages", "tool_calls", "type"),
        ("messages", "tool_calls", "function", "name"),
        ("tools", "type"),
        ("tools", "function", "name"),
        ("functions", "name"),
    }
    return keys in exact_paths


def _is_valid_protocol_string(path: tuple[PathPart, ...], value: str) -> bool:
    keys = tuple(part for part in path if isinstance(part, str))
    if keys == ("model",):
        return bool(MODEL_PATTERN.fullmatch(value))
    if keys == ("messages", "role"):
        return value in {"assistant", "developer", "function", "system", "tool", "user"}
    if keys in {
        ("messages", "tool_calls", "type"),
        ("tools", "type"),
    }:
        return value == "function"
    if keys in {
        ("messages", "tool_call_id"),
        ("messages", "tool_calls", "id"),
        ("messages", "tool_calls", "function", "name"),
        ("tools", "function", "name"),
        ("functions", "name"),
    }:
        return bool(IDENTIFIER_PATTERN.fullmatch(value))
    if keys == ("response_format", "type"):
        return value in {"json_object", "json_schema", "text"}
    return len(value) <= 256
