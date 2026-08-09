from __future__ import annotations

import asyncio
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from app.masking.anonymizer import MaskingSession

CONVERSATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


def validate_conversation_id(value: str | None) -> str | None:
    """Validate an opaque conversation capability before using it as a key."""
    if value is None or value == "":
        return None
    if not CONVERSATION_ID_PATTERN.fullmatch(value):
        raise ValueError("conversation_id must contain 8-128 letters, digits, '_' or '-'")
    return value


@dataclass(slots=True)
class ConversationState:
    conversation_id: str
    owner_id: str
    session: MaskingSession
    messages: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_access_at: float = field(default_factory=time.time)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def turn_count(self) -> int:
        return sum(1 for message in self.messages if message.get("role") == "user")


class InMemoryConversationStore:
    """Request-independent conversation state held only in process memory.

    The store contains masked messages plus the request-scoped vault needed to
    restore placeholders. It deliberately has no disk or network backend.
    """

    def __init__(
        self,
        ttl_seconds: int,
        max_messages: int = 40,
        max_chars: int = 120_000,
        max_conversations: int = 1_000,
    ) -> None:
        self.ttl_seconds = max(ttl_seconds, 1)
        self.max_messages = max(max_messages, 4)
        self.max_chars = max(max_chars, 1_000)
        self.max_conversations = max(max_conversations, 1)
        self._items: dict[tuple[str, str], ConversationState] = {}
        self._lock = threading.Lock()

    def _cleanup_locked(self, now: float) -> None:
        expired = [
            key
            for key, value in self._items.items()
            if value.last_access_at + self.ttl_seconds <= now
        ]
        for key in expired:
            del self._items[key]

    def get_or_create(
        self,
        conversation_id: str,
        owner_id: str,
        session_factory: Callable[[], MaskingSession],
    ) -> ConversationState:
        now = time.time()
        with self._lock:
            self._cleanup_locked(now)
            key = (owner_id, conversation_id)
            state = self._items.get(key)
            if state is None:
                if len(self._items) >= self.max_conversations:
                    raise ConversationCapacityExceeded
                state = ConversationState(conversation_id, owner_id, session_factory())
                self._items[key] = state
            state.last_access_at = now
            return state

    def commit(
        self,
        state: ConversationState,
        session: MaskingSession,
        messages: list[dict[str, Any]],
    ) -> None:
        trimmed = self._trim_messages(messages)
        now = time.time()
        with self._lock:
            if self._items.get((state.owner_id, state.conversation_id)) is not state:
                return
            state.session = session
            state.messages = trimmed
            state.last_access_at = now

    def delete(self, conversation_id: str, owner_id: str) -> None:
        with self._lock:
            self._items.pop((owner_id, conversation_id), None)

    def size(self) -> int:
        now = time.time()
        with self._lock:
            self._cleanup_locked(now)
            return len(self._items)

    def _trim_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        copied = [dict(message) for message in messages]
        if len(copied) > self.max_messages:
            system_messages = [message for message in copied if message.get("role") == "system"]
            non_system = [message for message in copied if message.get("role") != "system"]
            copied = system_messages[:2] + non_system[-max(self.max_messages - 2, 2) :]

        def size(items: list[dict[str, Any]]) -> int:
            return sum(len(str(message.get("content", ""))) for message in items)

        while len(copied) > 1 and size(copied) > self.max_chars:
            removable_index = next(
                (index for index, message in enumerate(copied) if message.get("role") != "system"),
                0,
            )
            copied.pop(removable_index)
        return copied


class ConversationCapacityExceeded(Exception):
    """The bounded in-memory conversation vault has no free slot."""
