from __future__ import annotations

from starlette.formparsers import MultiPartParser


def configure_strict_multipart_memory(max_body_bytes: int) -> None:
    """Keep every accepted multipart file in RAM before route parsing starts."""

    MultiPartParser.spool_max_size = max(
        MultiPartParser.spool_max_size,
        max(max_body_bytes, 1),
    )
