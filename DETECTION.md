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

PERSON, ORG, LOCATION, postal address, health data, date of birth, and broad multilingual names
do not yet have production-quality local NER. Some legacy PHONE and DOMAIN matches are known to
produce false positives.

## Evaluation

The versioned synthetic corpus is under `evaluation/corpus/` and is evaluated by:

```powershell
python -m evaluation.evaluate_detection --profile strict
```

Corpus metrics describe only that small reproducible corpus. They are not estimates of real-world
precision or recall. New recognizers require positive, negative, evasion, and overlap cases before
runtime enablement.
