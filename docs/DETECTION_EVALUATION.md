# Detection Evaluation

This report describes the synthetic MaskGate detection corpus. It does not claim real-world PII
recall, compliance certification, broad named-entity recognition, or perfect anonymization.

## Corpus

- Version: `2.0.0`
- Cases: 598
- Locale counts: English 187, Russian 177, Ukrainian 175, locale-neutral 59
- Required tags: positive 509, negative 61, hard-negative 60, multilingual 510,
  obfuscated 36, structured 242, valid 182, invalid 60
- Sources: hand-authored JSONL edge cases plus the declarative `quality.matrix.json`
- Matrix diversity: 19 groups and 49 unique sentence templates generate 563 of 598 cases

Matrix cases are deterministic template-by-value products. Each generated case has a unique ID and
full text, and the test suite rejects duplicates. This efficiently exercises many entity values in
multiple independent sentence fixtures, but the samples are highly correlated and must not be
treated as 598 statistically independent observations. Only 35 cases are hand-authored outside the
matrix and the matrix itself uses only 49 unique sentence templates. All names and identifiers are
synthetic or documentation fixtures. Perfect scores mean the implementation fits this regression
corpus; they provide no universal detection claim and must not be generalized to unseen text.

## Strict-profile snapshot

Measured locally with `python -m evaluation.evaluate_detection --profile strict`:

| Entity | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PERSON | 146 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ORG | 91 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| LOCATION | 94 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| POSTAL_ADDRESS | 73 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| DOB | 109 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| PHONE | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| DOMAIN | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |

The 28-case baseline exposed PHONE precision 0.50 and one DOMAIN false positive. Narrow contextual
phone validation and rejection of encoded dotted triplets remove those observed errors in v2.
These perfect synthetic-corpus rows are regression results, not estimates of production quality.

| Locale | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| en | 181 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ru | 176 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| uk | 173 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| und | 12 | 0 | 0 | 1.000 | 1.000 | 1.000 |

The evaluator's JSON also includes entity-within-locale and entity-within-category slices.

## Profile behavior and limitations

- `fast` accepts only high-confidence deterministic findings.
- `balanced` accepts validated and contextual findings at the normal threshold.
- `strict` includes lower-confidence ambiguous shapes and preserves the privacy bias.

Locale packs are deterministic and local-only. They use small name/location vocabularies, labels,
legal forms, postal structure, and calendar validation. They miss unseen vocabulary and nuanced
free-form language, and may still confuse title-cased phrases. They do not replace local statistical
NER, nor do they infer semantic identity from quasi-identifier combinations.
