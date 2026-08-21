# Detection

MaskGate detection is local and provider-independent. It does not call a remote model and does
not claim complete PII recall.

## Interface

`DetectorEnsemble` canonicalizes bounded text, runs local recognizers, merges exact findings,
and resolves overlaps. Each `PrivacyDetection` carries entity type, data class, original offsets,
confidence, recognizer, validation state, locale, evidence codes, and context score. Evidence
codes never contain the detected value.

Canonicalization applies NFKC, removes selected zero-width characters, converts non-breaking
spaces, and maintains a canonical-to-original span map. Input/output and expansion limits prevent
normalization DoS. Percent/base64/hex/nested-JSON handling is deliberately performed by the final
wire guard rather than unbounded recursive canonicalization.

## Profiles

Set `DETECTOR_PROFILE=fast|balanced|strict`. Invalid values become `strict`.

- `fast`: high-confidence findings only.
- `balanced`: validated identifiers and established regex findings.
- `strict`: lower-confidence ambiguous shapes may be returned and policy must decide; privacy is
  preferred over availability.

## Implemented recognizers

- Legacy patterns: e-mail, phone, URL, domain, IPv4, file path, API key, payment card, INN,
  money, and limited person-name patterns.
- Validators: Luhn, Russian INN, SNILS, and IBAN.
- Contextual shape: labeled and strict-mode bare Russian passport forms.
- Structured secrets: JWT, connection strings, and private-key headers.
- Network: parsed IPv6.
- Deterministic locale packs for Russian, Ukrainian, and English: labeled or
  dictionary-assisted `PERSON`, legal-form `ORG`, exact location lexicons,
  structured postal addresses, and context-labeled calendar-valid `DOB`.

The locale recognizer is deliberately not presented as production-quality broad NER. It covers a
conservative, explainable subset; unseen names, organizations without legal forms, inflected
locations outside the lexicons, and free-form addresses remain blind spots. Health data is not
implemented. Some legacy PHONE and DOMAIN matches are known to produce false positives.

## Evaluation

The versioned synthetic corpus is under `evaluation/corpus/` and is evaluated by:

```powershell
python -m evaluation.evaluate_detection --profile strict
```

Corpus v2 contains 598 fully synthetic cases across Russian, Ukrainian, English, and locale-neutral
fixtures. It includes positive, negative, hard-negative, structured valid/invalid, multilingual,
and zero-width-obfuscated cases. `quality.matrix.json` declaratively expands independent text
fixtures as a template-by-value Cartesian product; generated IDs and texts are checked for
uniqueness and expansion is deterministic. This provides broad regression coverage without a huge
copied JSONL file, but many cases remain correlated variants rather than independent real-world
samples. Corpus v2 has only 49 unique sentence templates across 19 matrix groups; 563 of 598 cases
come from matrix expansion. Therefore its perfect regression scores must not be generalized to
unseen text, and corpus precision and recall are not estimates of production quality.

The evaluator reports aggregate, per-entity, per-locale, per-entity-and-locale, per-category, and
per-entity-and-category counts. Weak categories remain visible rather than being averaged away.
Public domains, file paths, locations, and money can remain detected entities even when policy
chooses to allow them; entity recognition is not itself a policy or risk decision.

New recognizers require positive, negative, evasion, and overlap cases before runtime enablement.
