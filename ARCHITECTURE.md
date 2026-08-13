# MaskGate architecture

MaskGate is a self-hosted privacy enforcement proxy for remote AI providers. It is not a
certified DLP product and it does not claim perfect PII detection.

## Security invariants

1. No unapproved sensitive value may cross a documented remote-provider trust boundary.
2. The exact provider-specific body sent by a built-in transport is represented by a
   `PrivacyCheckedPayload` created after provider serialization.
3. Reversible mappings are bijective within their configured scope.
4. Only active vault-issued tokens may be restored, and only in authorized output fields.
5. Strict streaming applies the same output inspection as non-streaming by buffering supported
   text and tool arguments until complete.
6. Unknown encoded content, numeric user data, unsupported media, malformed output, and unsafe
   provider extensions fail closed on documented paths.

## Architectural vocabulary

- **Module** - cohesive code with one privacy responsibility.
- **Interface** - the small contract exposed by a Module.
- **Implementation** - one concrete strategy behind an Interface.
- **Depth** - complexity hidden behind a small Interface.
- **Seam** - the controlled join between Modules.
- **Adapter** - provider- or format-specific translation at a Seam.
- **Leverage** - one invariant protecting several call paths.
- **Locality** - policy and sensitive state remain close to their owners.

## Pipeline

```text
Client
  -> authentication, pseudonymous PrincipalContext, request limits
  -> structural traversal and bounded canonicalization
  -> local Detection Ensemble
  -> deterministic Privacy Risk Engine
  -> contextual Policy Engine v2
  -> tokenization / redaction / approved surrogate
  -> RAM-only mapping vault
  -> Canonical Privacy IR
  -> provider Adapter serialization
  -> FinalWirePrivacyGuard
  -> sealed PrivacyCheckedPayload bytes
  -> built-in remote transport
  -> bounded and validated provider response / SSE
  -> OutputPrivacyGuard
  -> authorized field-scoped rehydration
  -> Client
```

`PrivacyRuntime` joins detection, risk, policy, and transformation. `PrivacyPipeline` joins
Canonical IR, provider serialization, final wire validation, transport input, and output policy.
Built-in transports accept checked payloads; custom in-process test doubles receive a reparsed copy.

## Trust boundaries

| Boundary | Untrusted side | Enforced controls |
|---|---|---|
| Client -> MaskGate | body, headers, files | auth, principal resolution, host/rate/size limits |
| Request -> PrivacyRuntime | strings, keys, structures | bounded canonicalization, detection, risk, contextual policy |
| Canonical IR -> Adapter | typed masked content | safe subset, cross-provider/unknown-field rejection |
| Adapter -> provider | actual JSON body | target/token/encoded/numeric checks and sealed checked type |
| Provider -> MaskGate | JSON and SSE | byte bounds, strict envelope/event parsing, output inspection |
| Output guard -> client | content and tool data | new-PII redaction and authorized restoration |
| Process memory -> host | originals and mappings | RAM lifetime, principal scoping, budgets, TTL and pruning |

## Sensitive-data Locality

Original values may exist in the inbound request, the active request/conversation vault, local
media processing memory, and a final client response authorized by an active mapping. Provider-safe
conversation history contains tokens, not rehydrated originals.

Originals must not be included in provider bodies, structured logs, metrics, debug mapping output,
normal traces, or persisted files. Python memory cannot be reliably zeroized; host compromise,
swap, core dumps, and privileged process inspection remain outside the guarantee.

## Wire guard

The final guard serializes canonical JSON, reparses those exact bytes, and inspects the reparsed
representation. It rejects unapproved detected values, unissued tokens, base64/base64url/long-hex,
sensitive percent or Unicode escapes, unsafe nested JSON, unclassified numeric values, unsafe
targets, and non-canonical JSON. Built-in transports send the returned bytes with `content=...` and
do not serialize them again.

## Streaming and output

The strict streaming Implementation buffers every supported text, refusal, legacy function
argument, and tool-call argument field by choice/path. Complete fields receive the non-streaming
output policy. This trades first-token latency for privacy parity. Malformed events fail closed.

Provider output is inspected before restoration. Only active replacements in approved fields may
restore originals. Unknown tokens and newly generated PII are redacted. Provider-safe history is
stored before rehydration.

## Provider independence

The public route is OpenAI Chat Completions compatible. Runtime OpenAI-compatible Chat and Gemini
`generateContent` paths have exact serialized-body tests. Responses, Anthropic, and Gemini
Interactions Adapters are library-level until their response/transport integrations are complete.
See `PROVIDERS.md`.

## Vault and tenancy

The current vault Implementation is single-process RAM. Principal namespaces are derived from
credentials without storing the credential. The same conversation ID under two credentials creates
two isolated states. Mapping budgets, TTL, explicit deletion, and reference pruning minimize data.

A future distributed vault requires authenticated encryption, tenant key separation, expiry,
replay controls, bounded indexes, and a revised threat model. Plaintext Redis mappings are not an
acceptable Implementation.

## Media

Media is accepted only through the local anonymization route. PDF secure mode rasterizes pages;
images are rebuilt without source metadata; DOCX uses an allowlist of inspectable OPC parts and
rejects opaque package content. OCR and face detection remain best effort and local by default.

## Privacy-safe observability

The in-memory metrics Interface accepts enumerated metric/stage names and bounded taxonomy labels
only. It cannot receive raw prompts, sensitive values, model IDs, credentials, mappings, file paths,
or arbitrary labels.

## Deployment

Run one process behind TLS and outbound provider allowlisting. Multi-worker deployments do not share
conversation mappings. Production mode disables Playground/debug and requires auth, trusted hosts,
HTTPS provider URL, and configured provider credentials.
