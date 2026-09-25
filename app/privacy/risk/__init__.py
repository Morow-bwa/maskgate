"""Deterministic privacy-risk Module."""

from app.privacy.risk.engine import PrivacyRiskEngine
from app.privacy.risk.semantic import (
    GeneralizationCandidate,
    PrivacyRiskFinding,
    SemanticFeature,
    SemanticPrivacyRiskAnalyzer,
    SemanticRiskAssessment,
    apply_generalizations,
)

__all__ = [
    "GeneralizationCandidate",
    "PrivacyRiskEngine",
    "PrivacyRiskFinding",
    "SemanticFeature",
    "SemanticPrivacyRiskAnalyzer",
    "SemanticRiskAssessment",
    "apply_generalizations",
]
