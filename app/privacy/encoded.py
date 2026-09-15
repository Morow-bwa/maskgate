"""Bounded encoded views shared by both terminal privacy boundaries."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import unquote

MAX_ENCODED_TEXT_BYTES = 64 * 1024
MAX_ENCODED_DEPTH = 4
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
HEX_PATTERN = re.compile(r"(?:[0-9A-Fa-f]{2}){16,}")
PERCENT_ESCAPE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
UNICODE_ESCAPE_PATTERN = re.compile(r"\\u([0-9A-Fa-f]{4})")

# Exact vocabulary only: arbitrary user-defined member names still need inspection.
SCHEMA_KEYS = frozenset(
    {
        "additionalProperties",
        "additionalItems",
        "unevaluatedProperties",
        "unevaluatedItems",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "max_completion_tokens",
        "parallel_tool_calls",
    }
)


class EncodedContentViolation(ValueError):
    pass


def is_protocol_id(text: str, path: tuple[str | int, ...], *, output: bool) -> bool:
    """Recognize IDs only at exact protocol locations, never inside tool data."""
    prefix = None
    if output and path == ("id",):
        prefix = r"(?:resp_|chatcmpl-)"
    elif len(path) == 3 and isinstance(path[1], int):
        if output and path[0] == "output":
            prefix = (
                r"(?:msg|fc)_" if path[2] == "id" else (r"call_" if path[2] == "call_id" else None)
            )
        elif not output and path[0] == "input" and path[2] == "call_id":
            prefix = r"call_"
        elif not output and path[0] == "messages" and path[2] == "tool_call_id":
            prefix = r"call_"
    elif (
        not output
        and len(path) == 5
        and path[0] == "messages"
        and isinstance(path[1], int)
        and path[2] == "tool_calls"
        and isinstance(path[3], int)
        and path[4] == "id"
    ):
        prefix = r"call_"
    elif (
        output
        and len(path) == 6
        and path[0] == "choices"
        and isinstance(path[1], int)
        and path[2] in {"message", "delta"}
        and path[3] == "tool_calls"
        and isinstance(path[4], int)
        and path[5] == "id"
    ):
        prefix = r"call_"
    return prefix is not None and re.fullmatch(prefix + r"[A-Za-z0-9_-]{1,120}", text) is not None


def decoded_views(text: str, *, depth: int = 0, protocol: bool = False) -> tuple[Any, ...]:
    """Reject opaque/budget-exhausted fields; return inspectable decoded views.

    Short Base64 candidates are inspected when they decode to UTF-8, rather than
    blanket-rejected: ordinary schema words overlap that alphabet. Long opaque
    values remain unsupported. A protocol exemption only affects this heuristic.
    """
    if len(text.encode("utf-8")) > MAX_ENCODED_TEXT_BYTES:
        raise EncodedContentViolation("encoded inspection size limit exceeded")
    stripped = text.strip()
    if not stripped:
        return ()
    views: list[Any] = []
    if not protocol:
        if HEX_PATTERN.fullmatch(stripped):
            raise EncodedContentViolation("unsupported encoded content")
        if BASE64_PATTERN.fullmatch(stripped):
            if len(stripped) >= 24:
                raise EncodedContentViolation("unsupported encoded content")
            try:
                decoded = base64.b64decode(
                    stripped + "=" * (-len(stripped) % 4), altchars=b"-_", validate=True
                ).decode("utf-8")
            except (ValueError, UnicodeError):
                pass
            else:
                views.append(decoded)
    if PERCENT_ESCAPE_PATTERN.search(stripped):
        views.append(unquote(stripped, errors="strict"))
    if UNICODE_ESCAPE_PATTERN.search(stripped):
        views.append(UNICODE_ESCAPE_PATTERN.sub(lambda m: chr(int(m.group(1), 16)), stripped))
    if stripped[:1] in {"{", "[", '"'}:
        try:
            nested = json.loads(stripped)
        except json.JSONDecodeError:
            pass
        except (RecursionError, ValueError) as exc:
            raise EncodedContentViolation("encoded JSON exceeds inspection limits") from exc
        else:
            if isinstance(nested, (dict, list, str)):
                views.append(nested)
    views = [view for view in views if view != stripped]
    if views and depth >= MAX_ENCODED_DEPTH:
        raise EncodedContentViolation("encoded inspection depth limit exceeded")
    return tuple(views)
