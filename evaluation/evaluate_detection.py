from __future__ import annotations

import argparse
import itertools
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from app.privacy.detection import DetectorEnsemble
from app.privacy.detection.contract import PrivacyDetector
from app.privacy.models import DetectionContext, DetectorProfile


@dataclass(frozen=True, slots=True)
class ExpectedEntity:
    entity_type: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class CorpusCase:
    case_id: str
    corpus_version: str
    category: str
    locale: str
    text: str
    expected: tuple[ExpectedEntity, ...]
    tags: tuple[str, ...] = ()


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
    per_locale: dict[str, EntityMetrics]
    per_entity_locale: dict[str, dict[str, EntityMetrics]]
    per_category: dict[str, EntityMetrics]
    per_entity_category: dict[str, dict[str, EntityMetrics]]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2, sort_keys=True)


def load_corpus(root: Path) -> tuple[CorpusCase, ...]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported detection corpus schema")

    cases: list[CorpusCase] = []
    corpus_version = str(manifest["corpus_version"])
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
                    corpus_version=corpus_version,
                    category=corpus_file.stem,
                    locale=str(raw.get("locale", "und")),
                    text=text,
                    expected=expected,
                    tags=tuple(str(tag) for tag in raw.get("tags", ())),
                )
            )
    for matrix_file in sorted(root.glob("*.matrix.json")):
        raw_matrix = json.loads(matrix_file.read_text(encoding="utf-8"))
        category = str(raw_matrix["category"])
        for group in raw_matrix["groups"]:
            group_id = str(group["id"])
            locale = str(group.get("locale", "und"))
            entity_type = group.get("entity_type")
            expected_values = tuple(group.get("expected_values", ()))
            tags = tuple(str(tag) for tag in group.get("tags", ()))
            templates = tuple(str(template) for template in group["templates"])
            values = tuple(str(value) for value in group["values"])
            for template_index, value_index in itertools.product(
                range(len(templates)), range(len(values))
            ):
                case_id = f"{group_id}-{template_index + 1:02d}-{value_index + 1:02d}"
                if case_id in seen_ids:
                    raise ValueError(f"duplicate corpus id: {case_id}")
                seen_ids.add(case_id)
                value = values[value_index]
                text = templates[template_index].format(value=value)
                if entity_type is not None:
                    expected = _expected_value(str(entity_type), text, value)
                else:
                    expected = tuple(
                        _expected_entity(text, item, matrix_file, value_index + 1)
                        for item in expected_values
                        if str(item["value"]) in text
                    )
                cases.append(
                    CorpusCase(
                        case_id=case_id,
                        corpus_version=corpus_version,
                        category=category,
                        locale=locale,
                        text=text,
                        expected=expected,
                        tags=tags,
                    )
                )
    return tuple(cases)


def _expected_value(
    entity_type: str,
    text: str,
    value: str,
) -> tuple[ExpectedEntity, ...]:
    start = text.index(value)
    return (ExpectedEntity(entity_type, start, start + len(value)),)


def evaluate(
    detector: PrivacyDetector,
    cases: Iterable[CorpusCase],
) -> EvaluationReport:
    materialized = tuple(cases)
    counts: dict[str, list[int]] = {}
    locale_counts: dict[str, list[int]] = {}
    entity_locale_counts: dict[str, dict[str, list[int]]] = {}
    category_counts: dict[str, list[int]] = {}
    entity_category_counts: dict[str, dict[str, list[int]]] = {}
    for case in materialized:
        context = DetectionContext(locale=case.locale, profile=detector.profile)
        predicted = {
            (item.entity_type, item.start, item.end)
            for item in detector.analyze(case.text, context)
        }
        expected = {(item.entity_type, item.start, item.end) for item in case.expected}
        locale = _locale_language(case.locale)
        case_tp = case_fp = case_fn = 0
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
            locale_entity_totals = entity_locale_counts.setdefault(locale, {}).setdefault(
                entity_type, [0, 0, 0]
            )
            locale_entity_totals[0] += true_positive
            locale_entity_totals[1] += false_positive
            locale_entity_totals[2] += false_negative
            category_entity_totals = entity_category_counts.setdefault(
                case.category, {}
            ).setdefault(entity_type, [0, 0, 0])
            category_entity_totals[0] += true_positive
            category_entity_totals[1] += false_positive
            category_entity_totals[2] += false_negative
            case_tp += true_positive
            case_fp += false_positive
            case_fn += false_negative
        locale_totals = locale_counts.setdefault(locale, [0, 0, 0])
        locale_totals[0] += case_tp
        locale_totals[1] += case_fp
        locale_totals[2] += case_fn
        category_totals = category_counts.setdefault(case.category, [0, 0, 0])
        category_totals[0] += case_tp
        category_totals[1] += case_fp
        category_totals[2] += case_fn

    metrics = {entity_type: _metrics(*totals) for entity_type, totals in sorted(counts.items())}
    per_locale = {locale: _metrics(*totals) for locale, totals in sorted(locale_counts.items())}
    per_entity_locale = {
        locale: {
            entity_type: _metrics(*totals)
            for entity_type, totals in sorted(locale_entities.items())
        }
        for locale, locale_entities in sorted(entity_locale_counts.items())
    }
    per_category = {
        category: _metrics(*totals) for category, totals in sorted(category_counts.items())
    }
    per_entity_category = {
        category: {
            entity_type: _metrics(*totals)
            for entity_type, totals in sorted(category_entities.items())
        }
        for category, category_entities in sorted(entity_category_counts.items())
    }
    corpus_versions = {case.corpus_version for case in materialized}
    if len(corpus_versions) > 1:
        raise ValueError("mixed corpus versions are not supported")
    return EvaluationReport(
        corpus_version=next(iter(corpus_versions), "unknown"),
        profile=detector.profile.value,
        case_count=len(materialized),
        per_entity=metrics,
        per_locale=per_locale,
        per_entity_locale=per_entity_locale,
        per_category=per_category,
        per_entity_category=per_entity_category,
    )


def _locale_language(locale: str) -> str:
    normalized = locale.casefold().replace("_", "-")
    return normalized.split("-", 1)[0] if normalized else "und"


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
