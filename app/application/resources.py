from __future__ import annotations

import threading
from dataclasses import dataclass


class AdmissionError(RuntimeError):
    """An operation cannot be admitted within the configured RAM envelope."""


class GlobalCapacityExceeded(AdmissionError):
    pass


class PrincipalCapacityExceeded(AdmissionError):
    pass


class OperationCapacityExceeded(AdmissionError):
    pass


@dataclass(slots=True)
class AdmissionReservation:
    _controller: AdmissionController
    principal_id: str
    reserved_bytes: int
    _released: bool = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._controller.release(self)


class AdmissionController:
    """Bound aggregate in-flight operations and conservative memory reservations."""

    def __init__(
        self,
        *,
        global_max_operations: int,
        principal_max_operations: int,
        global_max_bytes: int,
        principal_max_bytes: int,
        operation_max_bytes: int,
    ) -> None:
        self.global_max_operations = max(global_max_operations, 1)
        self.principal_max_operations = max(principal_max_operations, 1)
        self.global_max_bytes = max(global_max_bytes, 1)
        self.principal_max_bytes = max(principal_max_bytes, 1)
        self.operation_max_bytes = max(operation_max_bytes, 1)
        self._active_operations = 0
        self._reserved_bytes = 0
        self._principal_operations: dict[str, int] = {}
        self._principal_bytes: dict[str, int] = {}
        self._draining = False
        self._lock = threading.Lock()

    def reserve(self, principal_id: str, requested_bytes: int) -> AdmissionReservation:
        amount = max(requested_bytes, 1)
        if amount > self.operation_max_bytes:
            raise OperationCapacityExceeded
        with self._lock:
            if self._draining:
                raise GlobalCapacityExceeded
            principal_operations = self._principal_operations.get(principal_id, 0)
            principal_bytes = self._principal_bytes.get(principal_id, 0)
            if (
                principal_operations >= self.principal_max_operations
                or principal_bytes + amount > self.principal_max_bytes
            ):
                raise PrincipalCapacityExceeded
            if (
                self._active_operations >= self.global_max_operations
                or self._reserved_bytes + amount > self.global_max_bytes
            ):
                raise GlobalCapacityExceeded
            self._active_operations += 1
            self._reserved_bytes += amount
            self._principal_operations[principal_id] = principal_operations + 1
            self._principal_bytes[principal_id] = principal_bytes + amount
        return AdmissionReservation(self, principal_id, amount)

    def release(self, reservation: AdmissionReservation) -> None:
        with self._lock:
            principal_id = reservation.principal_id
            self._active_operations = max(self._active_operations - 1, 0)
            self._reserved_bytes = max(
                self._reserved_bytes - reservation.reserved_bytes,
                0,
            )
            principal_operations = max(
                self._principal_operations.get(principal_id, 0) - 1,
                0,
            )
            principal_bytes = max(
                self._principal_bytes.get(principal_id, 0) - reservation.reserved_bytes,
                0,
            )
            if principal_operations:
                self._principal_operations[principal_id] = principal_operations
            else:
                self._principal_operations.pop(principal_id, None)
            if principal_bytes:
                self._principal_bytes[principal_id] = principal_bytes
            else:
                self._principal_bytes.pop(principal_id, None)

    def start_draining(self) -> None:
        with self._lock:
            self._draining = True

    @property
    def ready(self) -> bool:
        with self._lock:
            return not self._draining and self._active_operations < self.global_max_operations

    def snapshot(self) -> dict[str, int | bool]:
        with self._lock:
            return {
                "active_operations": self._active_operations,
                "reserved_bytes": self._reserved_bytes,
                "active_principals": len(self._principal_operations),
                "draining": self._draining,
            }
