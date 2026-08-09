from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class SafeJsonFormatter(logging.Formatter):
    """Emit only structured, explicitly supplied metadata.

    Callers must never put raw request/response text, mappings, or credentials in
    ``extra``. The formatter does not inspect arbitrary objects from a request.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in (
            "request_id",
            "model_length",
            "masking_mode",
            "detected_entities_count",
            "detected_entity_types",
            "policy_result",
            "latency_ms",
            "status_code",
            "error_type",
        ):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SafeJsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
