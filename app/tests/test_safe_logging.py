from __future__ import annotations

import json
import logging

from app.logging_config import SafeJsonFormatter


def test_safe_formatter_suppresses_unstructured_sensitive_messages() -> None:
    record = logging.LogRecord(
        "dependency",
        logging.ERROR,
        __file__,
        1,
        "provider failed for owner@example.com with sk-test-abcdefghijklmnop",
        (),
        None,
    )

    payload = json.loads(SafeJsonFormatter().format(record))

    assert payload["message"] == "log_suppressed"
    assert "owner@example.com" not in str(payload)
    assert "sk-test" not in str(payload)


def test_safe_formatter_preserves_structured_event_codes() -> None:
    record = logging.LogRecord(
        "maskgate",
        logging.INFO,
        __file__,
        1,
        "request_completed",
        (),
        None,
    )

    assert json.loads(SafeJsonFormatter().format(record))["message"] == "request_completed"
