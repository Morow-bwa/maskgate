from __future__ import annotations

from typing import Any

IMAGE_PART_TYPES = {
    "image",
    "image_url",
    "input_image",
    "screen",
    "screenshot",
}


class UnsafeMediaBlocked(Exception):
    """Raised when media has not passed a local redaction pipeline."""

    def __init__(self, media_type: str = "image") -> None:
        self.media_type = media_type
        super().__init__(
            "Image or screen content requires local OCR/redaction before it can be sent upstream"
        )


def reject_unsanitized_media(payload: dict[str, Any]) -> None:
    """Fail closed for image/screen parts until a local redactor is installed."""
    for message in payload.get("messages", []):
        content = message.get("content") if isinstance(message, dict) else None
        parts = content if isinstance(content, list) else [content]
        for part in parts:
            if isinstance(part, dict):
                part_type = str(part.get("type", "")).casefold()
                if part_type in IMAGE_PART_TYPES:
                    raise UnsafeMediaBlocked(part_type)
