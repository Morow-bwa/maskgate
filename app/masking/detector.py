from __future__ import annotations

from dataclasses import asdict, dataclass

from .regex_patterns import ENTITY_PRIORITY, PATTERNS, PatternSpec


@dataclass(frozen=True, slots=True)
class Entity:
    type: str
    text: str
    start: int
    end: int
    confidence: float = 1.0
    method: str = "regex"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _candidate_from_match(text: str, spec: PatternSpec, match: object) -> Entity:
    # ``match`` is a re.Match at runtime; keeping this helper small makes the
    # detector's overlap logic easy to test.
    regex_match = match  # type: ignore[assignment]
    if spec.capture_group:
        start, end = regex_match.span(spec.capture_group)
    else:
        start, end = regex_match.span()
    value = text[start:end].rstrip(".,;:!?)]}>")
    end = start + len(value)
    return Entity(
        type=spec.entity_type.value,
        text=value,
        start=start,
        end=end,
    )


def _overlaps(left: Entity, right: Entity) -> bool:
    return left.start < right.end and right.start < left.end


def resolve_overlaps(candidates: list[Entity]) -> list[Entity]:
    # Sort by priority first, then prefer the longer match at equal priority.
    ordered = sorted(
        candidates,
        key=lambda item: (
            -ENTITY_PRIORITY.get(item.type, 0),
            -(item.end - item.start),
            item.start,
        ),
    )
    selected: list[Entity] = []
    for candidate in ordered:
        if any(_overlaps(candidate, existing) for existing in selected):
            continue
        selected.append(candidate)
    return sorted(selected, key=lambda item: (item.start, item.end))


class RegexDetector:
    def __init__(self, patterns: tuple[PatternSpec, ...] = PATTERNS) -> None:
        self.patterns = patterns

    def detect(self, text: str) -> list[Entity]:
        candidates: list[Entity] = []
        for spec in self.patterns:
            for match in spec.pattern.finditer(text):
                entity = _candidate_from_match(text, spec, match)
                if entity.end > entity.start:
                    candidates.append(entity)
        return resolve_overlaps(candidates)
