from __future__ import annotations

import ipaddress
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

_IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f:]{3,}(?![0-9A-Za-z:])")


class NetworkRecognizer:
    name = "network-address"
    profiles = frozenset(DetectorProfile)

    def recognize(
        self,
        text: CanonicalText,
        context: DetectionContext,
    ) -> tuple[PrivacyDetection, ...]:
        detections: list[PrivacyDetection] = []
        for match in _IPV6_CANDIDATE.finditer(text.text):
            value = match.group()
            if value.count(":") < 2:
                continue
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.version != 6:
                continue
            detections.append(
                detection_from_span(
                    text,
                    entity_type="IP_ADDRESS",
                    data_class=DataClass.QUASI_IDENTIFIER,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.995,
                    recognizer=self.name,
                    context=context,
                    validation_state=ValidationState.VALID,
                    evidence=("ipv6-parser",),
                )
            )
        return tuple(detections)
