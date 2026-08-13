from __future__ import annotations

import base64
import json
import re

from app.privacy.models import (
    DataClass,
    DetectionContext,
    DetectorProfile,
    PrivacyDetection,
    ValidationState,
)

from ..canonical import CanonicalText
from .base import detection_from_span

_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?P<header>[A-Za-z0-9_-]{8,})\."
    r"(?P<payload>[A-Za-z0-9_-]{8,})\."
    r"(?P<signature>[A-Za-z0-9_-]{8,})"
    r"(?![A-Za-z0-9_-])"
)
_CONNECTION_URI = re.compile(
    r"(?i)(?<![\w])"
    r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|sqlserver)"
    r"://[^\s<>\"']+"
)
_CONNECTION_KV = re.compile(
    r"(?i)(?<!\w)(?:server|host|data source)\s*=\s*[^;\r\n]{1,200};"
    r"[^\r\n]{0,500}?(?:password|pwd)\s*=\s*[^;\s\r\n]{1,200}"
)
_PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)


class SecretRecognizer:
    name = "structured-secrets"
    profiles = frozenset(DetectorProfile)

    def recognize(
        self,
        text: CanonicalText,
        context: DetectionContext,
    ) -> tuple[PrivacyDetection, ...]:
        detections: list[PrivacyDetection] = []
        for match in _JWT.finditer(text.text):
            if not _is_json_segment(match.group("header")) or not _is_json_segment(
                match.group("payload")
            ):
                continue
            detections.append(
                self._detection(text, context, "JWT", match.start(), match.end(), "jwt-json")
            )
        for pattern, entity_type, evidence in (
            (_CONNECTION_URI, "CONNECTION_STRING", "connection-uri"),
            (_CONNECTION_KV, "CONNECTION_STRING", "connection-key-value"),
            (_PRIVATE_KEY_HEADER, "PRIVATE_KEY", "private-key-header"),
        ):
            detections.extend(
                self._detection(text, context, entity_type, match.start(), match.end(), evidence)
                for match in pattern.finditer(text.text)
            )
        return tuple(detections)

    def _detection(
        self,
        text: CanonicalText,
        context: DetectionContext,
        entity_type: str,
        start: int,
        end: int,
        evidence: str,
    ) -> PrivacyDetection:
        return detection_from_span(
            text,
            entity_type=entity_type,
            data_class=DataClass.AUTH_SECRET,
            start=start,
            end=end,
            confidence=0.995,
            recognizer=self.name,
            context=context,
            validation_state=ValidationState.VALID,
            evidence=(evidence,),
        )


def _is_json_segment(value: str) -> bool:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return isinstance(json.loads(decoded), dict)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False
