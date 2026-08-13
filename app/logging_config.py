from __future__ import annotations

import json
import logging
import math
import re
import sys
from datetime import datetime, timezone
from typing import Any

SAFE_EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SAFE_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
SAFE_TAXONOMY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
SAFE_MASKING_MODES = frozenset({"placeholder", "semantic_placeholder", "surrogate", "redact"})
SAFE_POLICY_RESULTS = frozenset({"ALLOW", "MASK", "REDACT", "BLOCK", "ERROR"})
MAX_ENTITY_TYPE_LABELS = 64


class SafeJsonFormatter(logging.Formatter):
    """Emit only structured, explicitly supplied metadata.

    Callers must never put raw request/response text, mappings, or credentials in
    ``extra``. The formatter does not inspect arbitrary objects from a request.
    """

    def format(self, record: logging.LogRecord) -> str:
        message = record.msg if isinstance(record.msg, str) and not record.args else ""
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message if SAFE_EVENT_PATTERN.fullmatch(message) else "log_suppressed",
        }
        request_id = getattr(record, "request_id", None)
        if isinstance(request_id, str) and SAFE_REQUEST_ID_PATTERN.fullmatch(request_id):
            payload["request_id"] = request_id
        for key in ("model_length", "detected_entities_count", "status_code"):
            value = getattr(record, key, None)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                payload[key] = value
        latency = getattr(record, "latency_ms", None)
        if (
            isinstance(latency, (int, float))
            and not isinstance(latency, bool)
            and math.isfinite(latency)
            and latency >= 0
        ):
            payload["latency_ms"] = latency
        masking_mode = getattr(record, "masking_mode", None)
        if isinstance(masking_mode, str) and masking_mode in SAFE_MASKING_MODES:
            payload["masking_mode"] = masking_mode
        policy_result = getattr(record, "policy_result", None)
        if isinstance(policy_result, str) and policy_result in SAFE_POLICY_RESULTS:
            payload["policy_result"] = policy_result
        error_type = getattr(record, "error_type", None)
        if isinstance(error_type, str):
            payload["error_type"] = (
                error_type if SAFE_EVENT_PATTERN.fullmatch(error_type) else "suppressed"
            )
        labels = getattr(record, "detected_entity_types", None)
        if isinstance(labels, (list, tuple)):
            payload["detected_entity_types"] = list(
                dict.fromkeys(
                    label
                    for label in labels[:MAX_ENTITY_TYPE_LABELS]
                    if isinstance(label, str) and SAFE_TAXONOMY_PATTERN.fullmatch(label)
                )
            )
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SafeJsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
