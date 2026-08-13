# Policy and privacy risk

Policy v2 separates entity type, data class, contextual risk, and transformation action.

## Runtime order

```text
PrivacyDetection -> PrivacyRiskEngine -> PolicyEngineV2 -> transformation
```

The deterministic risk Module receives detection metadata only. It increases risk for validated
direct identifiers, financial/authentication data, and combinations of distinct quasi-identifiers.
It never receives or transmits a raw prompt.

Policy context includes pseudonymous tenant, application, route, direction, provider, model,
jurisdiction, purpose, JSON path, role, confidence, risk, recognizer, and token scope. Rules have
unique priorities. Unknown data uses a `BLOCK` or `REQUIRE_REVIEW` default.

Implemented actions are `ALLOW`, `TOKENIZE`, `SURROGATE`, `REDACT`, `BLOCK`, and
`REQUIRE_REVIEW`. `GENERALIZE` and `HASH` exist in the schema but fail closed until an
Implementation and tests exist.

## Strict configuration

Set `POLICY_V2_FILE` to a version-2 YAML document. The loader rejects duplicate YAML keys,
unknown schema keys, unknown actions/entities, invalid ranges, duplicate rule IDs/priorities, and
context-blind public assertions. See `docs/policy-schema-v2.example.yaml`.

Without `POLICY_V2_FILE`, the legacy policy is converted by a narrow Adapter. Legacy `MASK`
becomes `TOKENIZE`; entity types absent from the legacy file are blocked.

## Public data

A public e-mail or famous person's name is not globally safe. A public assertion requires:

- an exact normalized SHA-256 value digest;
- tenant, application, direction, provider, and purpose scope;
- expiry and provenance;
- `ALLOW` as its only action.

An applicable `BLOCK` or `REQUIRE_REVIEW` rule takes precedence over an assertion. Assertions can
relax routine tokenization, not contextual prohibitions. The old global environment allowlists
remain a legacy API only and are not used by Policy v2 runtime decisions.
