from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from app.masking.detector import RegexDetector
from app.policies.policy_engine import PolicyBlocked

OPAQUE_TOKEN_PATTERN = re.compile(r"<MG:[A-Z2-7]{26}>")
BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
BASE64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]{24,}={0,2}")
HEX_PATTERN = re.compile(r"(?:[0-9A-Fa-f]{2}){16,}")
PERCENT_ESCAPE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
UNICODE_ESCAPE_PATTERN = re.compile(r"\\u([0-9A-Fa-f]{4})")
MAX_ENCODED_TEXT_BYTES = 64 * 1024
_CHECKED_PAYLOAD_SEAL = object()


class WirePrivacyViolation(PolicyBlocked):
    """The final serialized provider body violates a privacy invariant."""

    def __init__(self, message: str) -> None:
        self.entity_types = ["WIRE_GUARD"]
        Exception.__init__(self, message)


@dataclass(frozen=True, slots=True)
class PrivacyCheckedPayload:
    """A serialized provider payload that passed the final wire guard.

    Network transports accept this checked representation instead of arbitrary
    dictionaries. The bytes in ``body`` are the bytes that must be sent.
    """

    provider: str
    target: str
    body: bytes
    _seal: object

    def __post_init__(self) -> None:
        if self._seal is not _CHECKED_PAYLOAD_SEAL:
            raise TypeError("PrivacyCheckedPayload can only be created by FinalWirePrivacyGuard")

    @property
    def payload(self) -> dict[str, Any]:
        # Reparse the immutable serialized body so callers cannot mutate the
        # object that was inspected by the guard.
        value = json.loads(self.body)
        if not isinstance(value, dict):  # pragma: no cover - constructor invariant
            raise TypeError("checked provider payload is not an object")
        return value


class FinalWirePrivacyGuard:
    """Inspect the exact JSON body immediately before remote transport."""

    def __init__(self, detector: RegexDetector) -> None:
        self.detector = detector

    def check(
        self,
        *,
        provider: str,
        payload: dict[str, Any],
        target: str = "",
        approved_tokens: Iterable[str] = (),
        approved_values: Iterable[str] = (),
    ) -> PrivacyCheckedPayload:
        if target and (
            not target.startswith("/")
            or ".." in target
            or "\r" in target
            or "\n" in target
            or len(target) > 512
        ):
            raise WirePrivacyViolation("provider request target is unsafe")
        token_set = frozenset(approved_tokens)
        value_set = frozenset(approved_values)
        try:
            body = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            actual = json.loads(body)
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise WirePrivacyViolation("provider payload is not canonical JSON") from exc
        if not isinstance(actual, dict):
            raise WirePrivacyViolation("provider payload must be a JSON object")

        self._inspect(actual, (), provider, token_set, value_set)
        return PrivacyCheckedPayload(provider, target, body, _CHECKED_PAYLOAD_SEAL)

    def _inspect(
        self,
        value: Any,
        path: tuple[str | int, ...],
        provider: str,
        approved_tokens: frozenset[str],
        approved_values: frozenset[str],
    ) -> None:
        if isinstance(value, str):
            for token in OPAQUE_TOKEN_PATTERN.findall(value):
                if token not in approved_tokens:
                    raise WirePrivacyViolation(
                        f"unrecognized MaskGate token at {self._format_path(path)}"
                    )
            for entity in self.detector.detect(value):
                if entity.text not in approved_values:
                    raise WirePrivacyViolation(
                        f"unapproved {entity.type} at {self._format_path(path)}"
                    )
            encoded_candidate = value
            for token in approved_tokens:
                encoded_candidate = encoded_candidate.replace(token, "")
            # JSON member names are still checked for direct PII and forged
            # MaskGate tokens above. They are not opaque value containers:
            # decoding ordinary protocol names such as ``additionalProperties``
            # as Base64 creates false positives and breaks documented schemas.
            if not path or path[-1] != "<key>":
                self._inspect_encoded(
                    encoded_candidate,
                    path,
                    approved_tokens,
                    approved_values,
                )
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                self._inspect(item, (*path, index), provider, approved_tokens, approved_values)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                self._inspect(
                    str(key),
                    (*path, "<key>"),
                    provider,
                    approved_tokens,
                    approved_values,
                )
                self._inspect(
                    item,
                    (*path, str(key)),
                    provider,
                    approved_tokens,
                    approved_values,
                )
            return
        if isinstance(value, bool) or value is None:
            return
        if isinstance(value, (int, float)) and not self._is_safe_protocol_number(provider, path):
            raise WirePrivacyViolation(
                f"unclassified numeric value at {self._format_path(path)}"
            )

    def _inspect_encoded(
        self,
        text: str,
        path: tuple[str | int, ...],
        approved_tokens: frozenset[str],
        approved_values: frozenset[str],
    ) -> None:
        stripped = text.strip()
        if not stripped or len(stripped.encode("utf-8")) > MAX_ENCODED_TEXT_BYTES:
            return

        if BASE64_PATTERN.fullmatch(stripped) or BASE64URL_PATTERN.fullmatch(stripped):
            try:
                padded = stripped + "=" * (-len(stripped) % 4)
                decoder = (
                    base64.urlsafe_b64decode
                    if "-" in stripped or "_" in stripped
                    else base64.b64decode
                )
                decoder(padded, validate=False) if decoder is base64.b64decode else decoder(padded)
            except (ValueError, TypeError):
                pass
            else:
                raise WirePrivacyViolation(
                    f"unsupported encoded content at {self._format_path(path)}"
                )

        if HEX_PATTERN.fullmatch(stripped):
            raise WirePrivacyViolation(f"unsupported encoded content at {self._format_path(path)}")

        decoded_views: list[str] = []
        if len(PERCENT_ESCAPE_PATTERN.findall(stripped)) >= 2:
            from urllib.parse import unquote

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
            if isinstance(nested, (dict, list)):
                self._inspect(
                    nested,
                    (*path, "<encoded-json>"),
                    "encoded-json",
                    approved_tokens,
                    approved_values,
                )

        for decoded in decoded_views:
            if decoded == stripped:
                continue
            for entity in self.detector.detect(decoded):
                if entity.text not in approved_values:
                    raise WirePrivacyViolation(
                        f"encoded {entity.type} at {self._format_path(path)}"
                    )

    @staticmethod
    def _format_path(path: tuple[str | int, ...]) -> str:
        return "$" + "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in path)

    @staticmethod
    def _is_safe_protocol_number(provider: str, path: tuple[str | int, ...]) -> bool:
        keys = tuple(part for part in path if isinstance(part, str))
        common_chat = {
            ("frequency_penalty",),
            ("logprobs",),
            ("max_completion_tokens",),
            ("max_tokens",),
            ("n",),
            ("presence_penalty",),
            ("seed",),
            ("temperature",),
            ("top_logprobs",),
            ("top_p",),
        }
        gemini = {
            ("generationConfig", "candidateCount"),
            ("generationConfig", "maxOutputTokens"),
            ("generationConfig", "temperature"),
            ("generationConfig", "topK"),
            ("generationConfig", "topP"),
        }
        if provider in {
            "openai-compatible-chat",
            "openai-chat",
            "openai-chat-completions",
            "mock",
            "custom",
        }:
            return keys in common_chat
        if provider == "gemini-generate-content":
            return keys in gemini
        return False
