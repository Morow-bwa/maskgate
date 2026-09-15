from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from app.privacy.models import PrivacyAction


class SemanticFeature(StrEnum):
    PRECISE_AGE = "precise_age"
    PRECISE_DATE = "precise_date"
    RARE_ROLE = "rare_role"
    SMALL_LOCATION = "small_location"
    UNIQUE_EMPLOYER = "unique_employer"


@dataclass(frozen=True, slots=True)
class PrivacyRiskFinding:
    kind: str
    score: float
    features: tuple[SemanticFeature, ...]
    recommended_action: PrivacyAction


@dataclass(frozen=True, slots=True)
class GeneralizationCandidate:
    feature: SemanticFeature
    start: int
    end: int
    replacement: str


@dataclass(frozen=True, slots=True)
class SemanticRiskAssessment:
    findings: tuple[PrivacyRiskFinding, ...]
    generalizations: tuple[GeneralizationCandidate, ...]


_AGE = re.compile(
    r"\b(?P<age>1[89]|[2-8][0-9])(?:-year-old|-летн(?:ий|яя|ее)|-річн(?:ий|а|е))\b",
    re.I,
)
_DATE = re.compile(
    r"\b(?:on\s+)?(?:[0-2]?\d|3[01])\s+"
    r"(?:January|February|March|April|May|June|July|August|September|October|November|December)"
    r"\s+(?:19|20)\d{2}\b",
    re.I,
)
_RARE_ROLE = re.compile(
    r"\b(?:CFO|chief financial officer|финансов(?:ый|ого) директор|"
    r"фінансов(?:ий|ого) директор)\b",
    re.I,
)
_UNIQUE_EMPLOYER = re.compile(
    r"\b(?:the only|единственн(?:ого|ый|ая|ое)|єдин(?:ого|ий|а|е))\s+"
    r"(?:[\w-]+\s+){0,3}(?:factory|plant|завод|завода|заводу|фабрик[аи])\b",
    re.I,
)
_SMALL_LOCATION = re.compile(
    r"\b(?:town|city|город(?:е|а)?|міст(?:і|а)?)\b[^.!?\n]{0,48}"
    r"\b(?:(?:population|населени(?:ем|е)|населенням)\s*)?(?:of\s*)?"
    r"(?P<count>\d{1,3}(?:[ ,.]?\d{3})?)\b",
    re.I,
)


class SemanticPrivacyRiskAnalyzer:
    """Bounded local heuristics for compound quasi-identifier review.

    This is a deterministic risk signal, not NER, anonymity proof, or policy
    decision. It returns explicit candidates; it never mutates user text.
    """

    def __init__(self, *, max_text_chars: int = 32_768) -> None:
        self._max_text_chars = max(max_text_chars, 1_000)

    def analyze(self, text: str, *, locale: str = "und") -> SemanticRiskAssessment:
        del locale
        if len(text) > self._max_text_chars:
            raise ValueError("semantic analysis input exceeds configured limit")

        feature_set: set[SemanticFeature] = set()
        candidates: list[GeneralizationCandidate] = []
        for match in _AGE.finditer(text):
            feature_set.add(SemanticFeature.PRECISE_AGE)
            age = int(match.group("age"))
            decade = (age // 10) * 10
            candidates.append(
                GeneralizationCandidate(
                    SemanticFeature.PRECISE_AGE,
                    match.start(),
                    match.end(),
                    f"person aged {decade}-{decade + 9}",
                )
            )
        for match in _DATE.finditer(text):
            feature_set.add(SemanticFeature.PRECISE_DATE)
            candidates.append(
                GeneralizationCandidate(
                    SemanticFeature.PRECISE_DATE,
                    match.start(),
                    match.end(),
                    f"in {match.group(0)[-4:]}",
                )
            )
        if _RARE_ROLE.search(text):
            feature_set.add(SemanticFeature.RARE_ROLE)
        if _UNIQUE_EMPLOYER.search(text):
            feature_set.add(SemanticFeature.UNIQUE_EMPLOYER)
        for match in _SMALL_LOCATION.finditer(text):
            count = int(re.sub(r"\D", "", match.group("count")))
            if count <= 20_000:
                feature_set.add(SemanticFeature.SMALL_LOCATION)

        ordered = tuple(sorted(feature_set, key=lambda item: item.value))
        findings: tuple[PrivacyRiskFinding, ...] = ()
        if len(ordered) >= 3:
            score = min(0.95, round(0.35 + 0.15 * len(ordered), 2))
            action = PrivacyAction.REQUIRE_REVIEW if score >= 0.8 else PrivacyAction.GENERALIZE
            findings = (
                PrivacyRiskFinding(
                    kind="compound_quasi_identifier",
                    score=score,
                    features=ordered,
                    recommended_action=action,
                ),
            )
        return SemanticRiskAssessment(
            findings=findings,
            generalizations=tuple(sorted(candidates, key=lambda item: (item.start, item.end))),
        )


def apply_generalizations(
    text: str,
    candidates: Iterable[GeneralizationCandidate],
    *,
    allowed_features: frozenset[SemanticFeature],
) -> str:
    """Apply only candidates explicitly authorized by a caller's policy."""

    selected = sorted(
        (item for item in candidates if item.feature in allowed_features),
        key=lambda item: (item.start, item.end),
        reverse=True,
    )
    previous_start = len(text)
    result = text
    for item in selected:
        if not (0 <= item.start < item.end <= len(text)) or item.end > previous_start:
            raise ValueError("generalization candidates overlap or have invalid spans")
        result = result[: item.start] + item.replacement + result[item.end :]
        previous_start = item.start
    return result
