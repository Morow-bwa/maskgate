from __future__ import annotations

import time
from dataclasses import dataclass

from app.identity import PrincipalContext
from app.masking.anonymizer import MaskingSession
from app.masking.detector import Entity
from app.observability import PrivacyMetric, PrivacyMetrics, PrivacyStage
from app.privacy.detection import DetectorEnsemble
from app.privacy.models import (
    DetectionContext,
    PrivacyAction,
    PrivacyDetection,
    PrivacyDirection,
    RiskAssessment,
    TokenScope,
)
from app.privacy.policy import PolicyContext, PolicyDecision, PolicyEngineV2
from app.privacy.risk import PrivacyRiskEngine


@dataclass(frozen=True, slots=True)
class PrivacyRequestContext:
    route: str
    provider: str
    model: str
    jurisdiction: str
    purpose: str
    token_scope: TokenScope


@dataclass(frozen=True, slots=True)
class PrivacyTransformResult:
    text: str
    detections: tuple[PrivacyDetection, ...]
    decisions: tuple[PolicyDecision, ...]
    risk: RiskAssessment
    approved_originals: tuple[str, ...]


class PrivacyRuntime:
    """Provider-independent detection, risk, policy, and transformation Module."""

    def __init__(
        self,
        detector: DetectorEnsemble,
        risk_engine: PrivacyRiskEngine,
        policy_engine: PolicyEngineV2,
        metrics: PrivacyMetrics,
    ) -> None:
        self.detector = detector
        self.risk_engine = risk_engine
        self.policy_engine = policy_engine
        self.metrics = metrics

    def transform_text(
        self,
        text: str,
        *,
        session: MaskingSession,
        principal: PrincipalContext,
        request: PrivacyRequestContext,
        json_path: tuple[str | int, ...],
        role: str | None,
    ) -> PrivacyTransformResult:
        started = time.perf_counter()
        detection_context = DetectionContext(
            locale="und",
            profile=self.detector.profile,
            json_path=json_path,
            role=role,
            direction=PrivacyDirection.INPUT,
        )
        detections = tuple(self.detector.detect(text, detection_context))
        self.metrics.observe(PrivacyStage.DETECTION, time.perf_counter() - started)
        for detection in detections:
            self.metrics.increment(
                PrivacyMetric.DETECTIONS,
                taxonomy_label=detection.entity_type,
            )

        started = time.perf_counter()
        risk = self.risk_engine.assess(detections)
        self.metrics.observe(PrivacyStage.RISK, time.perf_counter() - started)

        started = time.perf_counter()
        decisions = tuple(
            self.policy_engine.decide(
                detection,
                PolicyContext(
                    tenant=principal.tenant_id,
                    application=principal.application_id,
                    route=request.route,
                    direction=PrivacyDirection.INPUT,
                    provider=request.provider,
                    model=request.model,
                    jurisdiction=request.jurisdiction,
                    purpose=request.purpose,
                    json_path=json_path,
                    role=role,
                    confidence=detection.confidence,
                    risk=risk,
                    recognizer=detection.recognizer,
                    token_scope=request.token_scope,
                ),
                value=text[detection.start : detection.end],
            )
            for detection in detections
        )
        self.metrics.observe(PrivacyStage.POLICY, time.perf_counter() - started)

        for decision in decisions:
            if decision.action is PrivacyAction.BLOCK:
                self.metrics.increment(PrivacyMetric.POLICY_BLOCKS)
            elif decision.action is PrivacyAction.REQUIRE_REVIEW:
                self.metrics.increment(PrivacyMetric.POLICY_REVIEWS)

        entities = [
            Entity(
                type=detection.entity_type,
                text=text[detection.start : detection.end],
                start=detection.start,
                end=detection.end,
                confidence=detection.confidence,
                method=detection.recognizer,
            )
            for detection in detections
        ]
        started = time.perf_counter()
        transformed = session.mask_text_with_actions(
            text,
            entities,
            [decision.action for decision in decisions],
        )
        self.metrics.observe(PrivacyStage.TOKENIZATION, time.perf_counter() - started)
        approved = tuple(
            entity.text
            for entity, decision in zip(entities, decisions, strict=True)
            if decision.action is PrivacyAction.ALLOW
        )
        return PrivacyTransformResult(transformed, detections, decisions, risk, approved)
