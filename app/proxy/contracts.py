from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TransportCapabilities:
    """Composition-time declaration of the upstream transport contract."""

    accepts_checked_payload: bool
    supports_streaming: bool
