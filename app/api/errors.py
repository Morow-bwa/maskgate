from __future__ import annotations


def error_payload(message: str, error_type: str, **extra: object) -> dict[str, object]:
    """Build the bounded public error envelope shared by API families."""

    return {"error": {"message": message, "type": error_type, **extra}}
