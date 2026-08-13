# Security engineering review

Date: 2026-08-13
Baseline: `75f840e`
Scope: privacy runtime, provider Adapters/transports, vault/conversations, output/streaming, media,
configuration, logs/metrics, deployment, dependencies, CI, and repository hygiene.

This is an internal engineering review of an educational project, not a penetration test,
certification, or legal compliance assessment.

## Verified findings addressed

### Reversible surrogate collision (P0)

Finite surrogate lists wrapped and could map different originals to the same replacement. Surrogate
generation is now unique and the vault enforces a bijection. Collision and repeated-generation tests
cover the invariant.

### Encoded, numeric, and post-Adapter wire bypasses (P0)

Recursive pre-Adapter masking alone could not guarantee the actual provider body. The final guard
now checks Adapter output, encoded views, nested JSON, token provenance, object keys, and numeric
field registries. Built-in transports accept sealed checked bytes. OpenAI and Gemini
`httpx.MockTransport` tests assert the exact sent body.

### Opaque DOCX content (P0)

Unknown OPC parts could preserve hidden data. DOCX uses a reviewed allowlist and rejects media,
embeds, macros, unknown opaque parts, duplicate entries, external relationships, and archive limit
violations.

### Token collision, injection, and metadata leakage (P1)

Default tokens now carry 128 random bits, no type, and no counter. Reserved token grammar in client
input blocks before provider access. Semantic placeholders are an explicit compatibility mode.

### Streaming and output gaps (P1)

Strict streaming covers every choice plus content, refusal, legacy function arguments, and modern
tool arguments. Provider output is inspected before restoration; new PII and unknown tokens are
redacted. Malformed successful responses and malformed events fail closed.

### Conversation retention and semantics (P1)

Provider-safe history retains structured assistant tool calls/results instead of only text.
Rehydrated originals are not written to history. Trimming prunes unreferenced mappings; TTL,
explicit deletion, capacity and sensitive-byte budgets are enforced with deterministic clocks.

### Authentication-only tenancy (P1)

`PrincipalContext` provides pseudonymous tenant/application/subject identity without retaining the
credential. Vault/conversation/rate-limit namespaces use it. Same conversation ID under different
keys is isolated by tests.

### Context-blind policy and public allowlists (P1)

Policy v2 uses principal, route, provider, model, purpose, path, role, confidence, risk, recognizer,
and token scope. Public status requires an exact hashed, scoped, expiring, provenanced assertion and
cannot override explicit block/review rules.

### Detection architecture and evasions (P1)

Detection now has a recognizer Interface, bounded NFKC/zero-width/NBSP canonicalization with span
provenance, validators, profiles, and a synthetic evaluation corpus. Metrics are corpus-specific;
real-world recall remains unknown.

### Unsafe logging and observability labels (P1)

Structured logging suppresses unapproved messages and logs event codes/allowlisted fields. Metrics
accept enum names and bounded taxonomy labels only; raw values, prompts, credentials, paths, and
arbitrary high-cardinality labels are absent from the Interface.

### Final red-team compatibility findings (P1)

The frozen-feature adversarial pass found two fail-closed interoperability defects, not data
disclosure: documented schema member names were misclassified as Base64, and the fixed OpenAI
stream `object` value was redacted as a domain. Dictionary keys still receive direct PII/token
checks but are no longer decoded as opaque values. Exact known protocol literals are preserved.
All 28 independent regression cases pass after the fixes.

## Rejected or narrowed suspected findings

- Mappings were not persisted to disk/Redis; the risk was stale in-memory lifetime, now minimized.
- Media was not automatically sent to the remote provider; its risk is local anonymization quality
  and hostile-file parsing.
- A provider-independent Adapter class does not equal runtime support. Only OpenAI-compatible Chat
  and Gemini `generateContent` have complete wired paths at this milestone.
- Local models remain out of project scope by design; masking them does not protect a remote trust
  boundary.

## Residual risks

- No production-quality local PERSON/ORG/LOCATION/address/health NER; regex/OCR/face false negatives
  and PHONE/DOMAIN false positives remain.
- Semantic re-identification from context is possible after direct identifiers are removed.
- Strict streaming buffers output and loses first-token latency.
- RAM is visible to a compromised host and cannot be reliably zeroized by Python.
- One worker is required for conversation mappings; there is no encrypted shared vault.
- Responses, Anthropic, and Gemini Interactions are Adapter-library surfaces, not complete public
  transport claims.
- Unsupported binary/media/provider extensions block. This is a compatibility limitation and a
  deliberate privacy property.

## Verification

The final local Windows run passed 274 tests with branch coverage enabled and 82.93% combined
coverage, above the 75f840e baseline of 81.81%. The strict 28-case detection corpus, 500-iteration
synthetic privacy benchmark, Ruff, compileall, isolated-project dependency audit, frontend build,
frontend audit, React Doctor, secret/history scan, and diff checks also passed. Docker is not
installed on this host, so Linux container build and CodeQL remain CI-authoritative. Exact commands
are in the README and final report.

See `ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/PRIVACY_GUARANTEES.md`, `DETECTION.md`,
`POLICY.md`, `PROVIDERS.md`, `VAULT.md`, and `MIGRATION.md`.
