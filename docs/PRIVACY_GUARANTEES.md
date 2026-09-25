# Privacy guarantees and limits

MaskGate is an educational, production-oriented privacy engineering project. It is not a certified
DLP product and does not claim complete PII detection.

## Guaranteed by architecture for documented surfaces

- Built-in HTTP transports accept a sealed `PrivacyCheckedPayload`; its bytes are created by the
  final guard after provider Adapter serialization and are sent without re-serialization.
- Empty/example provider credentials stop before network access.
- Reversible mappings are bijective, bounded, RAM-only, scoped to a pseudonymous principal and
  request/conversation, and explicitly deleted or expired.
- Opaque default tokens contain 128 random bits and expose no entity type or counter. Client input
  matching reserved token grammar is blocked.
- Provider output is inspected before restoration. Only active mappings in approved content/tool
  fields may restore originals; safe conversation history is stored before restoration.
- Unknown encoded content, unknown tokens, cross-provider extensions, unclassified numeric user
  values, unsupported chat media, malformed provider responses/streams, and Adapter schema drift
  fail closed on runtime-supported paths.
- Raw prompts, originals, mappings, inbound authorization, and provider credentials are excluded
  from structured application logs and privacy metrics.
- Provider exception text is never reflected to clients. Public upstream errors use a bounded
  local type/message registry, and provider output is inspected through literal and decoded views.

## Covered by tests

- Exact `httpx.MockTransport` bytes for OpenAI-compatible Chat, OpenAI Responses, and Gemini
  `generateContent` contain no fixture original and equal the canonical bytes returned by the final
  guard.
- Text in messages, object keys, nested metadata, tool descriptions, tool arguments, and structured
  JSON strings is transformed or blocked.
- Split tokens, multiple stream choices, refusal, legacy function arguments, modern tool arguments,
  malformed SSE, and invalid successful responses have regression tests.
- Surrogate uniqueness, token injection, dictionary-key restoration, vault budgets/TTL/pruning,
  same-conversation cross-principal isolation, and provider-generated PII are tested.
- DOCX opaque parts/active content, archive limits, PDFs, images, OCR/face paths, and media policy
  blocks have fail-closed tests for the documented formats.

Coverage applies to fixtures and documented data surfaces, not every possible real-world input.

## Best-effort detection

Detection uses bounded Unicode canonicalization, regex recognizers, deterministic RU/UK/EN locale
packs, context, and selected algorithm validators. OCR and frontal-face detection are local. These
methods can miss unusual or inflected names and locations, organizations without legal forms,
free-form addresses, transliteration, mixed scripts, distorted text, novel secrets, indirect
identifiers, low-quality scans, or non-frontal faces. The 598-case synthetic evaluation corpus is
reproducible regression evidence built from only 49 templates, not a production recall estimate.

## Operator responsibility

- Use TLS, restrict inbound access and provider egress, protect environment secrets, and run one
  worker while using the RAM conversation vault.
- Select strict policy/profile for high-risk data and review policy changes and sanitized files.
- Scope public-data assertions narrowly with provenance and expiry. An assertion intentionally
  permits that exact value to reach the selected remote provider.
- Rotate any credential disclosed outside the secret-management path.

## Explicitly out of scope

- A compromised host/runtime/dependency, privileged memory inspection, swap, or crash dumps.
- Perfect PII detection, semantic anonymity, or prevention of re-identification from remaining
  context.
- Audio, video, spreadsheets, legacy `.doc`, arbitrary binary chat attachments, and unverifiable
  embedded document objects.
- Shared/distributed vault state, multi-worker conversation consistency, regulatory certification,
  or legal compliance determination.
- OpenAI Responses streaming, built-in/remote provider tools, provider-managed state, annotations,
  media, citations, non-empty logprobs, and undocumented Responses output item types.

## Semantic risk advisory

`SemanticPrivacyRiskAnalyzer` is a bounded local heuristic API for combinations such as precise
age, rare role, small location, and unique employer. It returns findings and age/date
generalization candidates. It never changes user text by itself: `apply_generalizations` requires
an explicit set of policy-authorized feature types. This is an architecture seam and deterministic
first implementation, not broad language understanding or proof against re-identification.
