from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from app.privacy.detection import DetectorEnsemble
from app.privacy.models import DetectionContext, DetectorProfile


@dataclass(frozen=True, slots=True)
class ExpectedEntity:
    entity_type: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class CorpusCase:
    case_id: str
    category: str
    locale: str
    text: str
    expected: tuple[ExpectedEntity, ...]


@dataclass(frozen=True, slots=True)
class EntityMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    corpus_version: str
    profile: str
    case_count: int
    per_entity: dict[str, EntityMetrics]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2, sort_keys=True)


def load_corpus(root: Path) -> tuple[CorpusCase, ...]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported detection corpus schema")

    cases: list[CorpusCase] = []
    seen_ids: set[str] = set()
    for corpus_file in sorted(root.glob("*.jsonl")):
        for line_number, line in enumerate(
            corpus_file.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if not line.strip():
                continue
            raw = json.loads(line)
            case_id = str(raw["id"])
            if case_id in seen_ids:
                raise ValueError(f"duplicate corpus id: {case_id}")
            seen_ids.add(case_id)
            text = str(raw["text"])
            expected = tuple(
                _expected_entity(text, item, corpus_file, line_number)
                for item in raw.get("entities", [])
            )
            cases.append(
                CorpusCase(
                    case_id=case_id,
                    category=corpus_file.stem,
                    locale=str(raw.get("locale", "und")),
                    text=text,
                    expected=expected,
                )
            )
    return tuple(cases)


def evaluate(
    detector: DetectorEnsemble,
    cases: Iterable[CorpusCase],
) -> EvaluationReport:
    materialized = tuple(cases)
    counts: dict[str, list[int]] = {}
    for case in materialized:
        context = DetectionContext(locale=case.locale, profile=detector.profile)
        predicted = {
            (item.entity_type, item.start, item.end)
            for item in detector.detect(case.text, context)
        }
        expected = {
            (item.entity_type, item.start, item.end)
            for item in case.expected
        }
        for entity_type in {item[0] for item in predicted | expected}:
            entity_predicted = {item for item in predicted if item[0] == entity_type}
            entity_expected = {item for item in expected if item[0] == entity_type}
            true_positive = len(entity_predicted & entity_expected)
            false_positive = len(entity_predicted - entity_expected)
            false_negative = len(entity_expected - entity_predicted)
            totals = counts.setdefault(entity_type, [0, 0, 0])
            totals[0] += true_positive
            totals[1] += false_positive
            totals[2] += false_negative

    metrics = {
        entity_type: _metrics(*totals)
        for entity_type, totals in sorted(counts.items())
    }
    return EvaluationReport(
        corpus_version="1.0.0",
        profile=detector.profile.value,
        case_count=len(materialized),
        per_entity=metrics,
    )


def _expected_entity(
    text: str,
    raw: object,
    corpus_file: Path,
    line_number: int,
) -> ExpectedEntity:
    if not isinstance(raw, dict):
        raise ValueError(f"invalid entity in {corpus_file}:{line_number}")
    value = str(raw["value"])
    occurrence = int(raw.get("occurrence", 0))
    start = -1
    search_from = 0
    for _ in range(occurrence + 1):
        start = text.find(value, search_from)
        if start < 0:
            raise ValueError(f"expected value not found in {corpus_file}:{line_number}")
        search_from = start + len(value)
    return ExpectedEntity(str(raw["type"]), start, start + len(value))


def _metrics(true_positive: int, false_positive: int, false_negative: int) -> EntityMetrics:
    predicted_count = true_positive + false_positive
    expected_count = true_positive + false_negative
    precision = true_positive / predicted_count if predicted_count else 1.0
    recall = true_positive / expected_count if expected_count else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return EntityMetrics(
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate MaskGate local privacy detection")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).parent / "corpus",
    )
    parser.add_argument(
        "--profile",
        choices=[item.value for item in DetectorProfile],
        default=DetectorProfile.STRICT.value,
    )
    args = parser.parse_args()
    detector = DetectorEnsemble(profile=DetectorProfile(args.profile))
    print(evaluate(detector, load_corpus(args.corpus)).to_json())


if __name__ == "__main__":
    main()
