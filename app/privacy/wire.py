from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from app.policies.policy_engine import PolicyBlocked
from app.privacy.approvals import ApprovalContext, ScopedApproval
from app.privacy.detection import PrivacyDetector
from app.privacy.encoded import (
    MAX_ENCODED_TEXT_BYTES,
    SCHEMA_KEYS,
    EncodedContentViolation,
    decoded_views,
    is_protocol_id,
)
from app.privacy.models import DetectionContext, PrivacyDirection

OPAQUE_TOKEN_PATTERN = re.compile(r"<MG:[A-Z2-7]{26}>")
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

    def __init__(
        self,
        detector: PrivacyDetector,
        *,
        max_structure_depth: int = 64,
        max_nodes: int = 10_000,
    ) -> None:
        self.detector = detector
        self.max_structure_depth = max(max_structure_depth, 1)
        self.max_nodes = max(max_nodes, 1)

    def check(
        self,
        *,
        provider: str,
        payload: dict[str, Any],
        target: str = "",
        approved_tokens: Iterable[str] = (),
        approved_values: Iterable[str] = (),
        scoped_approvals: Iterable[ScopedApproval] = (),
        approval_context: ApprovalContext | None = None,
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
        approval_set = tuple(scoped_approvals)
        if approval_set and approval_context is None:
            raise WirePrivacyViolation("scoped approvals require trusted operation context")
        if approval_context is not None and approval_context.provider != provider:
            raise WirePrivacyViolation("approval context does not match provider target")
        try:
            body = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            actual = json.loads(body)
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise WirePrivacyViolation("provider payload is not canonical JSON") from exc
        if not isinstance(actual, dict):
            raise WirePrivacyViolation("provider payload must be a JSON object")

        self._inspect(
            actual,
            (),
            provider,
            token_set,
            value_set,
            approval_set,
            approval_context,
            work=[0],
        )
        return PrivacyCheckedPayload(provider, target, body, _CHECKED_PAYLOAD_SEAL)

    def _inspect(
        self,
        value: Any,
        path: tuple[str | int, ...],
        provider: str,
        approved_tokens: frozenset[str],
        approved_values: frozenset[str],
        scoped_approvals: tuple[ScopedApproval, ...],
        approval_context: ApprovalContext | None,
        encoded_depth: int = 0,
        *,
        structure_depth: int = 0,
        work: list[int] | None = None,
    ) -> None:
        if work is None:
            work = [0]
        work[0] += 1
        if work[0] > self.max_nodes or structure_depth > self.max_structure_depth:
            raise WirePrivacyViolation("provider payload exceeds structural inspection limits")
        if isinstance(value, str):
            if len(value.encode("utf-8")) > MAX_ENCODED_TEXT_BYTES:
                raise WirePrivacyViolation("encoded inspection size limit exceeded")
            for token in OPAQUE_TOKEN_PATTERN.findall(value):
                if token not in approved_tokens:
                    raise WirePrivacyViolation(
                        f"unrecognized MaskGate token at {self._format_path(path)}"
                    )
            for detection in self.detector.analyze(
                value,
                DetectionContext(
                    profile=self.detector.profile,
                    json_path=path,
                    direction=PrivacyDirection.INPUT,
                ),
            ):
                detected_value = value[detection.start : detection.end]
                is_scoped = approval_context is not None and any(
                    approval.approves(
                        value=detected_value,
                        entity_type=detection.entity_type,
                        path=path,
                        context=approval_context,
                    )
                    for approval in scoped_approvals
                )
                if detected_value not in approved_values and not is_scoped:
                    label = "encoded" if encoded_depth else "unapproved"
                    raise WirePrivacyViolation(
                        f"{label} {detection.entity_type} at {self._format_path(path)}"
                    )
            encoded_candidate = value
            for token in approved_tokens:
                encoded_candidate = encoded_candidate.replace(token, "")
            try:
                self._inspect_encoded(
                    encoded_candidate,
                    path,
                    approved_tokens,
                    approved_values,
                    scoped_approvals,
                    approval_context,
                    encoded_depth,
                    structure_depth=structure_depth,
                    work=work,
                    protocol=(
                        (path and path[-1] == "<key>" and value in SCHEMA_KEYS)
                        or (
                            provider
                            in {
                                "openai-responses",
                                "openai-compatible-chat",
                                "openai-chat",
                                "openai-chat-completions",
                            }
                            and is_protocol_id(value, path, output=False)
                        )
                    ),
                )
            except (EncodedContentViolation, UnicodeError) as exc:
                raise WirePrivacyViolation("unsupported encoded content") from exc
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                self._inspect(
                    item,
                    (*path, index),
                    provider,
                    approved_tokens,
                    approved_values,
                    scoped_approvals,
                    approval_context,
                    encoded_depth,
                    structure_depth=structure_depth + 1,
                    work=work,
                )
            return
        if isinstance(value, dict):
            for key, item in value.items():
                self._inspect(
                    str(key),
                    (*path, "<key>"),
                    provider,
                    approved_tokens,
                    approved_values,
                    scoped_approvals,
                    approval_context,
                    encoded_depth,
                    structure_depth=structure_depth + 1,
                    work=work,
                )
                self._inspect(
                    item,
                    (*path, str(key)),
                    provider,
                    approved_tokens,
                    approved_values,
                    scoped_approvals,
                    approval_context,
                    encoded_depth,
                    structure_depth=structure_depth + 1,
                    work=work,
                )
            return
        if isinstance(value, bool) or value is None:
            return
        if isinstance(value, (int, float)) and not self._is_safe_protocol_number(provider, path):
            raise WirePrivacyViolation(f"unclassified numeric value at {self._format_path(path)}")

    def _inspect_encoded(
        self,
        text: str,
        path: tuple[str | int, ...],
        approved_tokens: frozenset[str],
        approved_values: frozenset[str],
        scoped_approvals: tuple[ScopedApproval, ...],
        approval_context: ApprovalContext | None,
        encoded_depth: int = 0,
        *,
        structure_depth: int = 0,
        work: list[int] | None = None,
        protocol: bool = False,
    ) -> None:
        for decoded in decoded_views(text, depth=encoded_depth, protocol=protocol):
            self._inspect(
                decoded,
                (*path, "<decoded>"),
                "encoded-json",
                approved_tokens,
                approved_values,
                scoped_approvals,
                approval_context,
                encoded_depth + 1,
                structure_depth=structure_depth + 1,
                work=work,
            )

    @staticmethod
    def _format_path(path: tuple[str | int, ...]) -> str:
        return "$" + "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in path)

    @staticmethod
    def _is_safe_protocol_number(provider: str, path: tuple[str | int, ...]) -> bool:
        keys = path
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
        openai_responses = {
            ("max_output_tokens",),
            ("temperature",),
            ("top_p",),
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
        if provider == "openai-responses":
            return keys in openai_responses
        return False
