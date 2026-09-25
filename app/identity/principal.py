from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PrincipalContext:
    """Pseudonymous identity carried across policy, rate-limit, and vault Modules."""

    tenant_id: str
    application_id: str
    subject_id: str
    authentication_method: str

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("application_id", self.application_id),
            ("subject_id", self.subject_id),
            ("authentication_method", self.authentication_method),
        ):
            if not value or not value.strip():
                raise ValueError(f"principal {name} must be non-empty")

    @property
    def vault_namespace(self) -> str:
        return f"{self.tenant_id}:{self.application_id}:{self.subject_id}"

    @property
    def rate_limit_key(self) -> str:
        return f"principal:{_digest(self.vault_namespace)}"

    @property
    def audit_id(self) -> str:
        return _digest(self.vault_namespace)[:24]


class PrincipalResolver(Protocol):
    def resolve(
        self,
        *,
        authorization: str | None,
        client_host: str | None,
    ) -> PrincipalContext: ...


class DefaultPrincipalResolver:
    """Privacy-first local resolver.

    Each configured bearer credential becomes a separate pseudonymous tenant.
    A future IAM Adapter may map authenticated subjects to shared tenant IDs
    without changing the policy or vault Interfaces.
    """

    def __init__(self, application_id: str = "maskgate") -> None:
        if not application_id.strip():
            raise ValueError("application_id must be non-empty")
        self._application_id = application_id.strip()

    def resolve(
        self,
        *,
        authorization: str | None,
        client_host: str | None,
    ) -> PrincipalContext:
        if authorization:
            scheme, separator, token = authorization.partition(" ")
            secret = (
                token if separator and scheme.casefold() == "bearer" and token else authorization
            )
            fingerprint = _digest(secret)
            return PrincipalContext(
                tenant_id=f"credential:{fingerprint[:32]}",
                application_id=self._application_id,
                subject_id=f"credential:{fingerprint[32:]}",
                authentication_method="bearer",
            )

        host_fingerprint = _digest(client_host or "unknown")
        return PrincipalContext(
            tenant_id="local",
            application_id=self._application_id,
            subject_id=f"client:{host_fingerprint[:32]}",
            authentication_method="local",
        )
