from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from app.masking.anonymizer import MaskingSession
from app.observability import PrivacyMetric, PrivacyMetrics

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
    generation: int
    revision: int = 0
    messages: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.monotonic)
    last_access_at: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    lease_count: int = 0
    revoked: bool = False
    accounted_bytes: int = 0

    @property
    def turn_count(self) -> int:
        return sum(1 for message in self.messages if message.get("role") == "user")


@dataclass(frozen=True, slots=True)
class ConversationCommit:
    generation: int
    revision: int
    message_count: int


class ConversationLifecycleError(RuntimeError):
    """A conversation operation no longer owns publish/restore authority."""


class ConversationRevoked(ConversationLifecycleError):
    """The leased generation was deleted, expired, or replaced."""


class ConversationStaleRevision(ConversationLifecycleError):
    """The private snapshot no longer matches the published revision."""


class ConversationModeMismatch(ConversationLifecycleError):
    """An existing conversation cannot change masking mode."""


class ConversationLockTimeout(ConversationLifecycleError):
    """The bounded wait for the conversation writer lock expired."""


@dataclass(slots=True)
class ConversationLease:
    """Non-transferable in-process authority for one serialized conversation turn."""

    _store: InMemoryConversationStore
    state: ConversationState
    generation: int
    revision: int
    _closed: bool = False
    _publish_reserved_bytes: int = 0

    @property
    def active(self) -> bool:
        return not self._closed and self._store.is_active(self)

    def require_active(self) -> None:
        self._store.require_active(self)

    def commit(
        self,
        session: MaskingSession,
        messages: list[dict[str, Any]],
    ) -> ConversationCommit:
        result = self._store.commit(self, session, messages)
        self.revision = result.revision
        return result

    def reserve_publish(
        self,
        session: MaskingSession,
        messages: list[dict[str, Any]],
        response_max_bytes: int,
    ) -> int:
        return self._store.reserve_publish(self, session, messages, response_max_bytes)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._store.release(self)

    async def __aenter__(self) -> ConversationLease:
        self.require_active()
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()


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
        *,
        clock: Callable[[], float] = time.monotonic,
        max_total_bytes: int = 64 * 1024 * 1024,
        max_owner_bytes: int = 16 * 1024 * 1024,
        metrics: PrivacyMetrics | None = None,
    ) -> None:
        self.ttl_seconds = max(ttl_seconds, 1)
        self.max_messages = max(max_messages, 4)
        self.max_chars = max(max_chars, 1_000)
        self.max_conversations = max(max_conversations, 1)
        self.max_total_bytes = max(max_total_bytes, 1_024)
        self.max_owner_bytes = max(max_owner_bytes, 1_024)
        self._clock = clock
        self._items: dict[tuple[str, str], ConversationState] = {}
        self._lock = threading.Lock()
        self._generation = 0
        self._accounted_bytes = 0
        self._owner_bytes: dict[str, int] = {}
        self._publish_reserved_bytes = 0
        self._owner_publish_reserved_bytes: dict[str, int] = {}
        self._metrics = metrics

    def _cleanup_locked(self, now: float) -> None:
        expired = [
            key
            for key, value in self._items.items()
            if (
                value.lease_count == 0
                and not value.lock.locked()
                and value.last_access_at + self.ttl_seconds <= now
            )
        ]
        for key in expired:
            state = self._items.pop(key)
            self._revoke_locked(state)

    def _new_state_locked(
        self,
        conversation_id: str,
        owner_id: str,
        session_factory: Callable[[], MaskingSession],
        now: float,
    ) -> ConversationState:
        if len(self._items) >= self.max_conversations:
            raise ConversationCapacityExceeded
        self._generation += 1
        state = ConversationState(
            conversation_id,
            owner_id,
            session_factory(),
            generation=self._generation,
            created_at=now,
            last_access_at=now,
        )
        self._items[(owner_id, conversation_id)] = state
        return state

    def _revoke_locked(self, state: ConversationState) -> None:
        self._accounted_bytes = max(self._accounted_bytes - state.accounted_bytes, 0)
        owner_bytes = max(
            self._owner_bytes.get(state.owner_id, 0) - state.accounted_bytes,
            0,
        )
        if owner_bytes:
            self._owner_bytes[state.owner_id] = owner_bytes
        else:
            self._owner_bytes.pop(state.owner_id, None)
        state.accounted_bytes = 0
        state.revoked = True
        state.messages.clear()
        state.session.clear()
        if self._metrics is not None:
            self._metrics.increment(PrivacyMetric.STATE_REVOCATIONS)
            self._metrics.increment(PrivacyMetric.VAULT_DELETIONS)

    def get_or_create(
        self,
        conversation_id: str,
        owner_id: str,
        session_factory: Callable[[], MaskingSession],
    ) -> ConversationState:
        now = self._clock()
        with self._lock:
            self._cleanup_locked(now)
            key = (owner_id, conversation_id)
            state = self._items.get(key)
            if state is None:
                state = self._new_state_locked(
                    conversation_id,
                    owner_id,
                    session_factory,
                    now,
                )
            state.last_access_at = now
            return state

    async def begin_turn(
        self,
        conversation_id: str,
        owner_id: str,
        session_factory: Callable[[], MaskingSession],
        *,
        requested_mode: str,
        timeout_seconds: float | None = None,
    ) -> ConversationLease:
        """Reserve and acquire the only writer for the current generation."""
        now = self._clock()
        with self._lock:
            self._cleanup_locked(now)
            key = (owner_id, conversation_id)
            state = self._items.get(key)
            if state is None:
                state = self._new_state_locked(
                    conversation_id,
                    owner_id,
                    session_factory,
                    now,
                )
            elif state.session.mode != requested_mode:
                raise ConversationModeMismatch
            state.lease_count += 1

        acquired = False
        try:
            if timeout_seconds is None:
                await state.lock.acquire()
            else:
                try:
                    await asyncio.wait_for(
                        state.lock.acquire(),
                        timeout=max(timeout_seconds, 0.0),
                    )
                except TimeoutError as exc:
                    raise ConversationLockTimeout from exc
            acquired = True
            with self._lock:
                if self._items.get(key) is not state or state.revoked:
                    raise ConversationRevoked
                state.last_access_at = self._clock()
                return ConversationLease(
                    self,
                    state,
                    state.generation,
                    state.revision,
                )
        except BaseException:
            if acquired:
                state.lock.release()
            with self._lock:
                state.lease_count = max(state.lease_count - 1, 0)
            raise

    def commit(
        self,
        lease: ConversationLease,
        session: MaskingSession,
        messages: list[dict[str, Any]],
    ) -> ConversationCommit:
        if not isinstance(lease, ConversationLease):
            raise ConversationStaleRevision("commit requires an active conversation lease")
        trimmed = self._trim_messages(messages)
        session.prune_to_references(trimmed)
        retained_bytes = self._messages_size(trimmed) + session.estimated_bytes
        now = self._clock()
        with self._lock:
            state = lease.state
            self._require_active_locked(lease)
            if state.revision != lease.revision:
                raise ConversationStaleRevision
            delta = retained_bytes - state.accounted_bytes
            owner_bytes = self._owner_bytes.get(state.owner_id, 0)
            other_reserved = self._publish_reserved_bytes - lease._publish_reserved_bytes
            owner_other_reserved = (
                self._owner_publish_reserved_bytes.get(state.owner_id, 0)
                - lease._publish_reserved_bytes
            )
            if (
                self._accounted_bytes + delta + other_reserved > self.max_total_bytes
                or owner_bytes + delta + owner_other_reserved > self.max_owner_bytes
            ):
                if self._metrics is not None:
                    self._metrics.increment(PrivacyMetric.VAULT_CAPACITY_REJECTIONS)
                raise ConversationMemoryCapacityExceeded
            self._release_publish_reservation_locked(lease)
            state.session = session
            state.messages = trimmed
            state.revision += 1
            state.last_access_at = now
            state.accounted_bytes = retained_bytes
            self._accounted_bytes += delta
            self._owner_bytes[state.owner_id] = owner_bytes + delta
            return ConversationCommit(
                generation=state.generation,
                revision=state.revision,
                message_count=len(trimmed),
            )

    def reserve_publish(
        self,
        lease: ConversationLease,
        session: MaskingSession,
        messages: list[dict[str, Any]],
        response_max_bytes: int,
    ) -> int:
        """Reserve the worst retained-state delta before provider I/O."""
        trimmed = self._trim_messages(messages)
        message_bytes = min(
            self._messages_size(trimmed) + max(response_max_bytes, 0),
            self.max_chars,
        )
        upper_bound = message_bytes + session.estimated_bytes
        with self._lock:
            self._require_active_locked(lease)
            if lease.revision != lease.state.revision:
                raise ConversationStaleRevision
            if lease._publish_reserved_bytes:
                raise ConversationStaleRevision("publish capacity is already reserved")
            amount = max(upper_bound - lease.state.accounted_bytes, 0)
            owner_reserved = self._owner_publish_reserved_bytes.get(lease.state.owner_id, 0)
            if (
                self._accounted_bytes + self._publish_reserved_bytes + amount
                > self.max_total_bytes
                or self._owner_bytes.get(lease.state.owner_id, 0) + owner_reserved + amount
                > self.max_owner_bytes
            ):
                if self._metrics is not None:
                    self._metrics.increment(PrivacyMetric.VAULT_CAPACITY_REJECTIONS)
                raise ConversationMemoryCapacityExceeded
            lease._publish_reserved_bytes = amount
            self._publish_reserved_bytes += amount
            self._owner_publish_reserved_bytes[lease.state.owner_id] = owner_reserved + amount
            return amount

    def _release_publish_reservation_locked(self, lease: ConversationLease) -> None:
        amount = lease._publish_reserved_bytes
        if not amount:
            return
        owner_id = lease.state.owner_id
        self._publish_reserved_bytes = max(self._publish_reserved_bytes - amount, 0)
        owner_reserved = max(
            self._owner_publish_reserved_bytes.get(owner_id, 0) - amount,
            0,
        )
        if owner_reserved:
            self._owner_publish_reserved_bytes[owner_id] = owner_reserved
        else:
            self._owner_publish_reserved_bytes.pop(owner_id, None)
        lease._publish_reserved_bytes = 0

    def _require_active_locked(self, lease: ConversationLease) -> None:
        state = lease.state
        current = self._items.get((state.owner_id, state.conversation_id))
        if (
            lease._closed
            or current is not state
            or state.revoked
            or state.generation != lease.generation
        ):
            raise ConversationRevoked

    def require_active(self, lease: ConversationLease) -> None:
        with self._lock:
            self._require_active_locked(lease)

    def is_active(self, lease: ConversationLease) -> bool:
        try:
            self.require_active(lease)
        except ConversationLifecycleError:
            return False
        return True

    def release(self, lease: ConversationLease) -> None:
        state = lease.state
        with self._lock:
            self._release_publish_reservation_locked(lease)
            state.lease_count = max(state.lease_count - 1, 0)
            if not state.revoked:
                state.last_access_at = self._clock()
        if state.lock.locked():
            state.lock.release()

    def delete(self, conversation_id: str, owner_id: str) -> None:
        with self._lock:
            state = self._items.pop((owner_id, conversation_id), None)
            if state is not None:
                self._revoke_locked(state)

    def delete_owner(self, owner_id: str) -> int:
        """Delete every in-memory conversation vault owned by one tenant scope."""
        with self._lock:
            owned_keys = [key for key in self._items if key[0] == owner_id]
            for key in owned_keys:
                state = self._items.pop(key)
                self._revoke_locked(state)
            return len(owned_keys)

    def size(self) -> int:
        now = self._clock()
        with self._lock:
            self._cleanup_locked(now)
            return len(self._items)

    def snapshot(self) -> dict[str, int]:
        """Return fixed aggregate counters without conversation or principal labels."""
        now = self._clock()
        with self._lock:
            self._cleanup_locked(now)
            return {
                "conversations": len(self._items),
                "active_leases": sum(state.lease_count for state in self._items.values()),
                "retained_bytes": self._accounted_bytes,
                "reserved_publish_bytes": self._publish_reserved_bytes,
            }

    def touch(self, state: ConversationState) -> None:
        with self._lock:
            if self._items.get((state.owner_id, state.conversation_id)) is state:
                state.last_access_at = self._clock()

    def cleanup(self) -> int:
        now = self._clock()
        with self._lock:
            before = len(self._items)
            self._cleanup_locked(now)
            return before - len(self._items)

    def _trim_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        copied = [dict(message) for message in messages]
        if len(copied) > self.max_messages:
            system_messages = [message for message in copied if message.get("role") == "system"]
            non_system = [message for message in copied if message.get("role") != "system"]
            copied = system_messages[:2] + non_system[-max(self.max_messages - 2, 2) :]

        while copied and self._messages_size(copied) > self.max_chars:
            removable_index = next(
                (index for index, message in enumerate(copied) if message.get("role") != "system"),
                0,
            )
            copied.pop(removable_index)
        return copied

    def _messages_size(self, items: list[dict[str, Any]]) -> int:
        try:
            return len(
                json.dumps(
                    items,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        except (TypeError, ValueError, UnicodeError):
            # Unsupported retained objects must not acquire an unknown size.
            return self.max_chars + 1


class ConversationCapacityExceeded(Exception):
    """The bounded in-memory conversation vault has no free slot."""


class ConversationMemoryCapacityExceeded(ConversationCapacityExceeded):
    """Publishing a turn would exceed aggregate retained-state capacity."""
