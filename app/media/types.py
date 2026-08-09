from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


class MediaSanitizationError(Exception):
    def __init__(self, error_type: str, message: str, status_code: int = 400) -> None:
        self.error_type = error_type
        self.message = message
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class MediaSanitizationResult:
    content: bytes
    media_type: str
    filename: str
    redactions: int
    entity_types: tuple[str, ...]


def safe_output_stem(filename: str, fallback: str) -> str:
    """Return an ASCII-only attachment stem safe for HTTP response headers."""
    stem = PurePosixPath((filename or "").replace("\\", "/")).stem
    sanitized = "".join(
        char for char in stem if char.isascii() and (char.isalnum() or char in "-_")
    )[:60]
    return sanitized or fallback
