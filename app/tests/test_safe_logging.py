from __future__ import annotations

import json
import logging

import pytest

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


def test_safe_formatter_suppresses_sensitive_values_in_structured_extras() -> None:
    synthetic_email = "telemetry.owner@example.com"
    record = logging.LogRecord(
        "maskgate",
        logging.ERROR,
        __file__,
        1,
        "request_completed",
        (),
        None,
    )
    record.request_id = synthetic_email
    record.error_type = f"provider_error:{synthetic_email}"
    record.detected_entity_types = ["EMAIL", synthetic_email]

    serialized = SafeJsonFormatter().format(record)

    assert synthetic_email not in serialized


class _HostileString:
    def __str__(self) -> str:
        return "object.owner@example.com"


class _ExplosiveString:
    def __str__(self) -> str:
        raise RuntimeError("must not stringify log content")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", _HostileString()),
        ("error_type", _HostileString()),
        ("masking_mode", _HostileString()),
        ("policy_result", _HostileString()),
        ("detected_entity_types", [_HostileString()]),
        ("model_length", _HostileString()),
        ("detected_entities_count", _HostileString()),
        ("latency_ms", _HostileString()),
        ("status_code", _HostileString()),
    ],
)
def test_safe_formatter_never_stringifies_arbitrary_extra_objects(
    field: str,
    value: object,
) -> None:
    record = logging.LogRecord("maskgate", logging.INFO, __file__, 1, "request_completed", (), None)
    setattr(record, field, value)

    serialized = SafeJsonFormatter().format(record)

    assert "object.owner@example.com" not in serialized


def test_safe_formatter_bounds_entity_type_cardinality_and_length() -> None:
    record = logging.LogRecord("maskgate", logging.INFO, __file__, 1, "request_completed", (), None)
    record.detected_entity_types = [
        *[f"ENTITY_{index}" for index in range(300)],
        "A" * 65,
        "telemetry.owner@example.com",
    ]

    payload = json.loads(SafeJsonFormatter().format(record))

    labels = payload["detected_entity_types"]
    assert len(labels) <= 64
    assert all(len(label) <= 64 for label in labels)
    assert "telemetry.owner@example.com" not in str(payload)


def test_safe_formatter_suppresses_non_string_messages_and_format_arguments() -> None:
    formatter = SafeJsonFormatter()
    object_message = logging.LogRecord(
        "maskgate", logging.ERROR, __file__, 1, _ExplosiveString(), (), None
    )
    format_argument = logging.LogRecord(
        "maskgate", logging.ERROR, __file__, 1, "provider_error_%s", (_ExplosiveString(),), None
    )

    assert json.loads(formatter.format(object_message))["message"] == "log_suppressed"
    assert json.loads(formatter.format(format_argument))["message"] == "log_suppressed"
