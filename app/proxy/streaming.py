from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.masking.anonymizer import MappingItem
from app.masking.rehydrator import rehydrate_text
from app.privacy.output_guard import OutputPrivacyGuard


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


StreamPath = tuple[str | int, ...]


class BufferedStreamingOutputGuard:
    """Apply non-streaming output semantics to fragmented OpenAI-style fields.

    Strict privacy mode buffers text and structured tool arguments until the
    provider finishes. This intentionally trades first-token latency for the
    same inspection and restoration semantics as a non-streaming response.
    """

    def __init__(self, output_guard: OutputPrivacyGuard, mapping: list[MappingItem]) -> None:
        self.output_guard = output_guard
        self.mapping = mapping
        self._buffers: dict[StreamPath, str] = {}
        self._last_event: dict[StreamPath, dict[str, Any]] = {}

    def push(self, event: dict[str, Any]) -> dict[str, Any]:
        updated = deepcopy(event)
        for path in self._text_paths(updated):
            value = self._get(updated, path)
            if not isinstance(value, str):
                continue
            self._buffers[path] = self._buffers.get(path, "") + value
            self._last_event[path] = deepcopy(event)
            self._set(updated, path, "")
        return self.output_guard.process(updated, self.mapping)

    def finish_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for path, text in self._buffers.items():
            safe_text = self.output_guard.process_authorized_text(text, self.mapping)
            if not safe_text:
                continue
            event = self._empty_event_for(path)
            self._set(event, path, safe_text)
            events.append(event)
        self._buffers.clear()
        self._last_event.clear()
        return events

    def provider_text(self) -> str:
        return self._buffers.get(("choices", 0, "delta", "content"), "")

    @classmethod
    def _text_paths(cls, event: dict[str, Any]) -> list[StreamPath]:
        paths: list[StreamPath] = []
        choices = event.get("choices")
        if not isinstance(choices, list):
            return paths
        for choice_index, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            for field in ("content", "refusal"):
                if isinstance(delta.get(field), str):
                    paths.append(("choices", choice_index, "delta", field))
            function_call = delta.get("function_call")
            if isinstance(function_call, dict) and isinstance(function_call.get("arguments"), str):
                paths.append(("choices", choice_index, "delta", "function_call", "arguments"))
            tool_calls = delta.get("tool_calls")
            if isinstance(tool_calls, list):
                for tool_index, tool_call in enumerate(tool_calls):
                    if not isinstance(tool_call, dict):
                        continue
                    function = tool_call.get("function")
                    if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                        paths.append(
                            (
                                "choices",
                                choice_index,
                                "delta",
                                "tool_calls",
                                tool_index,
                                "function",
                                "arguments",
                            )
                        )
        return paths

    @staticmethod
    def _get(value: Any, path: StreamPath) -> Any:
        current = value
        for part in path:
            current = current[part]
        return current

    @staticmethod
    def _set(value: Any, path: StreamPath, replacement: str) -> None:
        current = value
        for part in path[:-1]:
            current = current[part]
        current[path[-1]] = replacement

    @staticmethod
    def _empty_event_for(path: StreamPath) -> dict[str, Any]:
        choice_index = int(path[1])
        delta: dict[str, Any] = {}
        if path[3] in {"content", "refusal"}:
            delta[str(path[3])] = ""
        elif path[3] == "function_call":
            delta["function_call"] = {"arguments": ""}
        else:
            tool_index = int(path[4])
            delta["tool_calls"] = [
                {"index": index, "function": {"arguments": ""}} for index in range(tool_index + 1)
            ]
        choices = [
            {"index": index, "delta": {}, "finish_reason": None}
            for index in range(choice_index + 1)
        ]
        choices[choice_index]["delta"] = delta
        return {"object": "chat.completion.chunk", "choices": choices}
