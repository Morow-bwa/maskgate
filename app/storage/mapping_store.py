from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from app.masking.anonymizer import MappingItem


@dataclass(frozen=True, slots=True)
class RequestMapping:
    request_id: str
    created_at: float
    expires_at: float
    items: tuple[MappingItem, ...]


class InMemoryMappingStore:
    """Request-scoped mapping store; never writes mapping data to disk or logs."""

    def __init__(self, ttl_seconds: int, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._items: dict[str, RequestMapping] = {}
        self._lock = threading.Lock()

    def _cleanup_locked(self, now: float) -> None:
        expired = [key for key, value in self._items.items() if value.expires_at <= now]
        for key in expired:
            del self._items[key]

    def put(self, request_id: str, items: list[MappingItem]) -> RequestMapping:
        now = self._clock()
        mapping = RequestMapping(
            request_id,
            now,
            now + self.ttl_seconds,
            tuple(item for item in items if item.restore),
        )
        with self._lock:
            self._cleanup_locked(now)
            self._items[request_id] = mapping
        return mapping

    def get(self, request_id: str) -> RequestMapping | None:
        now = self._clock()
        with self._lock:
            self._cleanup_locked(now)
            return self._items.get(request_id)

    def delete(self, request_id: str) -> None:
        with self._lock:
            self._items.pop(request_id, None)

    def size(self) -> int:
        now = self._clock()
        with self._lock:
            self._cleanup_locked(now)
            return len(self._items)

    def cleanup(self) -> int:
        now = self._clock()
        with self._lock:
            before = len(self._items)
            self._cleanup_locked(now)
            return before - len(self._items)
