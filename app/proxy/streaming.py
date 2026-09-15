from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from app.masking.anonymizer import MappingItem
from app.masking.rehydrator import rehydrate_text
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.pipeline import ProviderOutputViolation
from app.providers import ProviderAdapterError
from app.providers.openai_chat import (
    OpenAIChatCompletionsAdapter,
    validate_chat_completion_response,
)


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
            safe = self.buffer[: -len(hold)]
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


@dataclass(frozen=True, slots=True)
class FinalizedStream:
    """Separate inspected client events from provider-safe retained state."""

    events: tuple[dict[str, Any], ...]
    history_message: dict[str, Any] | None


class BufferedStreamingOutputGuard:
    """Buffer complete fields by semantic choice/tool index before inspection."""

    def __init__(
        self,
        output_guard: OutputPrivacyGuard,
        mapping: list[MappingItem],
        *,
        require_replayable_history: bool = False,
    ) -> None:
        self.output_guard = output_guard
        self.mapping = mapping
        self.require_replayable_history = require_replayable_history
        self._messages: dict[int, dict[str, Any]] = {}
        self._tools: dict[int, dict[int, dict[str, Any]]] = {}
        self._finished: dict[int, str] = {}
        self._closed = False

    @staticmethod
    def _invalid() -> ProviderOutputViolation:
        return ProviderOutputViolation("upstream_invalid_stream")

    @classmethod
    def _index(cls, value: Any) -> int:
        if type(value) is not int or value < 0:
            raise cls._invalid()
        return value

    @classmethod
    def _append(cls, target: dict[str, Any], field: str, value: Any) -> None:
        if not isinstance(value, str):
            raise cls._invalid()
        target[field] = target.get(field, "") + value

    def push(self, event: dict[str, Any]) -> dict[str, Any]:
        if self._closed or "error" in event:
            raise self._invalid()
        try:
            OpenAIChatCompletionsAdapter().parse_stream_event(event)
        except ProviderAdapterError as exc:
            raise self._invalid() from exc
        updated = deepcopy(event)
        seen: set[int] = set()
        for position, choice in enumerate(event["choices"]):
            index = self._index(choice.get("index", position))
            if index in seen or index in self._finished:
                raise self._invalid()
            seen.add(index)
            message = self._messages.setdefault(index, {"role": "assistant"})
            delta = choice.get("delta", {})
            empty: dict[str, Any] = {}
            for field in ("content", "refusal"):
                if delta.get(field) is not None:
                    self._append(message, field, delta[field])
                    empty[field] = ""
            if delta.get("function_call") is not None:
                function = message.setdefault("function_call", {})
                for field, value in delta["function_call"].items():
                    self._append(function, field, value)
                empty["function_call"] = {"arguments": ""}
            seen_tools: set[int] = set()
            for tool_position, tool in enumerate(delta.get("tool_calls", [])):
                tool_index = self._index(tool.get("index", tool_position))
                if tool_index in seen_tools:
                    raise self._invalid()
                seen_tools.add(tool_index)
                stored = self._tools.setdefault(index, {}).setdefault(tool_index, {})
                if "id" in tool:
                    self._append(stored, "id", tool["id"])
                if "type" in tool:
                    if tool["type"] != "function":
                        raise self._invalid()
                    stored["type"] = "function"
                function = stored.setdefault("function", {})
                for field, value in tool.get("function", {}).items():
                    self._append(function, field, value)
                empty.setdefault("tool_calls", []).append(
                    {"index": tool_index, "function": {"arguments": ""}}
                )
            reason = choice.get("finish_reason")
            if reason is not None:
                if not isinstance(reason, str) or reason not in {
                    "stop", "length", "tool_calls", "function_call", "content_filter",
                }:
                    raise self._invalid()
                self._finished[index] = reason
            updated["choices"][position] = {
                "index": index, "delta": empty, "finish_reason": None,
            }
        return self.output_guard.process(updated, self.mapping)

    def finalize(self) -> FinalizedStream:
        if self._closed:
            raise self._invalid()
        self._closed = True
        try:
            if not self._messages or self._messages.keys() != self._finished.keys():
                raise self._invalid()
            choices = []
            for index, message in self._messages.items():
                message = deepcopy(message)
                if index in self._tools:
                    message["tool_calls"] = [
                        deepcopy(tool) for _, tool in sorted(self._tools[index].items())
                    ]
                # A terminal-only stream is a valid empty assistant response.
                if len(message) == 1:
                    message["content"] = ""
                choices.append({"index": index, "message": message})
            envelope = {"choices": choices}
            validate_chat_completion_response(envelope)
            safe = self.output_guard.sanitize_for_history(envelope, self.mapping)
            saw_choice_zero = False
            if self.require_replayable_history:
                for safe_choice in safe["choices"]:
                    if safe_choice["index"] == 0:
                        saw_choice_zero = True
                if not saw_choice_zero:
                    raise self._invalid()
            client = self.output_guard.process(safe, self.mapping)
            events = []
            history_message = None
            for safe_choice, client_choice in zip(safe["choices"], client["choices"], strict=True):
                index = safe_choice["index"]
                if index == 0:
                    candidate = safe_choice["message"]
                    if self.require_replayable_history:
                        candidate = self._replayable_history_message(candidate)
                    if candidate != {"role": "assistant", "content": ""}:
                        history_message = deepcopy(candidate)
                delta = deepcopy(client_choice["message"])
                if "tool_calls" in delta:
                    for tool_index, tool in zip(
                        sorted(self._tools[index]), delta["tool_calls"], strict=True,
                    ):
                        tool["index"] = tool_index
                events.append({"object": "chat.completion.chunk", "choices": [
                    {"index": index, "delta": delta, "finish_reason": None},
                ]})
            # Finish markers follow every buffered field, never precede content.
            events.append({"object": "chat.completion.chunk", "choices": [
                {"index": index, "delta": {}, "finish_reason": reason}
                for index, reason in self._finished.items()
            ]})
            return FinalizedStream(tuple(events), history_message)
        except (ProviderAdapterError, ValueError, RecursionError) as exc:
            raise self._invalid() from exc
        finally:
            self._messages.clear()
            self._tools.clear()
            self._finished.clear()

    @classmethod
    def _replayable_history_message(cls, message: dict[str, Any]) -> dict[str, Any]:
        normalized = deepcopy(message)
        if "function_call" in normalized:
            # The reviewed request adapter deliberately does not support the
            # legacy function_call message field. Retaining it would make the
            # next turn fail only after history had already been published.
            raise cls._invalid()
        if "refusal" in normalized:
            refusal = normalized.pop("refusal")
            if normalized.get("content") not in (None, ""):
                raise cls._invalid()
            normalized["content"] = refusal

        seen_ids: set[str] = set()
        for tool in normalized.get("tool_calls", []):
            call_id = tool.get("id")
            function = tool.get("function")
            if not isinstance(call_id, str) or not call_id or call_id in seen_ids:
                raise cls._invalid()
            seen_ids.add(call_id)
            if not isinstance(function, dict) or not isinstance(function.get("name"), str):
                raise cls._invalid()
            try:
                arguments = json.loads(function.get("arguments"))
            except (TypeError, ValueError, RecursionError) as exc:
                raise cls._invalid() from exc
            if not isinstance(arguments, dict):
                raise cls._invalid()
        return normalized

    def finish_events(self) -> list[dict[str, Any]]:
        return list(self.finalize().events)
