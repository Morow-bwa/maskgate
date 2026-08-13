from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Iterable, Protocol

from app.policies.policy_engine import PolicyBlocked


@dataclass(frozen=True, slots=True)
class MappingItem:
    entity_type: str
    original: str
    replacement: str
    restore: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "entity_type": self.entity_type,
            "replacement": self.replacement,
            "reversible": self.restore,
        }


@dataclass(frozen=True, slots=True)
class VaultBudget:
    max_mappings: int = 5_000
    max_sensitive_bytes: int = 2 * 1024 * 1024


class VaultCapacityExceeded(PolicyBlocked):
    def __init__(self) -> None:
        self.entity_types = ["VAULT_CAPACITY"]
        Exception.__init__(self, "Sensitive mapping capacity exceeded")


class VaultCollision(PolicyBlocked):
    def __init__(self) -> None:
        self.entity_types = ["VAULT_COLLISION"]
        Exception.__init__(self, "Reversible mapping collision detected")


class Vault(Protocol):
    @property
    def items(self) -> tuple[MappingItem, ...]: ...

    def find_original(self, original: str) -> MappingItem | None: ...

    def add(self, item: MappingItem) -> None: ...

    def prune_to_references(self, values: Iterable[Any]) -> None: ...


class InMemoryVault:
    """Bounded, bijective, process-local mapping vault Implementation."""

    def __init__(self, budget: VaultBudget) -> None:
        self.budget = budget
        self._items: list[MappingItem] = []
        self._by_original: dict[str, MappingItem] = {}
        self._by_replacement: dict[str, MappingItem] = {}
        self._sensitive_bytes = 0
        self._lock = RLock()

    @property
    def items(self) -> tuple[MappingItem, ...]:
        with self._lock:
            return tuple(self._items)

    def find_original(self, original: str) -> MappingItem | None:
        with self._lock:
            return self._by_original.get(original)

    def contains_original(self, value: str) -> bool:
        with self._lock:
            return value in self._by_original

    def contains_replacement(self, value: str) -> bool:
        with self._lock:
            return value in self._by_replacement

    def add(self, item: MappingItem) -> None:
        with self._lock:
            existing = self._by_original.get(item.original)
            if existing is not None:
                if existing != item:
                    raise VaultCollision
                return
            reverse = self._by_replacement.get(item.replacement)
            if item.restore and reverse is not None and reverse.original != item.original:
                raise VaultCollision
            sensitive_bytes = len(item.original.encode("utf-8"))
            if len(self._items) >= max(
                self.budget.max_mappings, 1
            ) or self._sensitive_bytes + sensitive_bytes > max(
                self.budget.max_sensitive_bytes, 1_024
            ):
                raise VaultCapacityExceeded
            self._items.append(item)
            self._by_original[item.original] = item
            if item.restore:
                self._by_replacement[item.replacement] = item
            self._sensitive_bytes += sensitive_bytes

    def prune_to_references(self, values: Iterable[Any]) -> None:
        strings = tuple(self._iter_strings(values))
        with self._lock:
            retained = [
                item
                for item in self._items
                if item.restore and any(item.replacement in value for value in strings)
            ]
            self._items = retained
            self._by_original = {item.original: item for item in retained}
            self._by_replacement = {item.replacement: item for item in retained}
            self._sensitive_bytes = sum(len(item.original.encode("utf-8")) for item in retained)

    def __deepcopy__(self, memo: dict[int, Any]) -> InMemoryVault:
        with self._lock:
            cloned = type(self)(self.budget)
            cloned._items = list(self._items)
            cloned._by_original = dict(self._by_original)
            cloned._by_replacement = dict(self._by_replacement)
            cloned._sensitive_bytes = self._sensitive_bytes
        memo[id(self)] = cloned
        return cloned

    @classmethod
    def _iter_strings(cls, values: Iterable[Any]) -> Iterable[str]:
        for value in values:
            if isinstance(value, str):
                yield value
            elif isinstance(value, list):
                yield from cls._iter_strings(value)
            elif isinstance(value, dict):
                for key, item in value.items():
                    if isinstance(key, str):
                        yield key
                    yield from cls._iter_strings((item,))
