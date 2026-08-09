# Threat model

## Scope

MaskGate protects supported sensitive values while a client uses a remote LLM API. The trusted computing base is the MaskGate host, its process memory, its configuration, and the operator-controlled network path to it.

## Assets

- Original prompts, file contents, and conversation mappings.
- Provider and MaskGate API keys.
- Sanitized outbound payloads and restored responses.
- Process availability and conversation isolation.

## Trust boundaries

1. Client to MaskGate: untrusted input enters authentication, size, host, and rate controls.
2. Application to provider: the recursive outbound sanitizer is the final privacy boundary before HTTP serialization.
3. Upload to local media pipeline: hostile archives, PDFs, and images enter bounded parsers and must be verified before download.
4. Process memory: originals and placeholder mappings exist here temporarily but must not reach logs or disk.

## Considered attackers

- An unauthenticated or abusive network client.
- A legitimate tenant trying to read another tenant's conversation state.
- A malicious prompt using tool fields, metadata, object keys, or protocol identifiers to bypass message-only masking.
- A malformed or decompression-bomb file attempting resource exhaustion or parser abuse.
- An honest-but-curious or compromised remote provider that can inspect every received byte.
- Accidental repository publication of credentials.

## Security properties

- Every string value and object key in the outbound JSON is inspected. Known protocol identifiers pass only after PII inspection and grammar validation.
- Unsafe or ambiguous protocol fields block the request before the provider client is called.
- Client authorization is replaced with the configured provider credential and is never forwarded.
- Conversation state is keyed by a hash-derived client identity plus conversation ID, bounded by TTL/count/size, and kept in RAM.
- Media is never sent upstream automatically. Unsupported or unverifiable formats fail closed.
- Production refuses to start without inbound authentication, explicit trusted hosts, and disabled Playground/debug routes.

## Out of scope

- A compromised MaskGate host, administrator, dependency, Python runtime, or memory dump.
- Network confidentiality without operator-provided TLS.
- Perfect PII/face/OCR recall, semantic inference, or re-identification from non-PII context.
- Distributed conversation state, multi-worker consistency, or cross-region replication.
- Sanitizing audio, video, spreadsheets, legacy `.doc`, or arbitrary embedded DOCX objects.
- Regulatory certification.

## Acceptance criteria

- Tests inspect the serialized mock-provider request body and prove known originals are absent.
- Detector, policy, protocol, media, and capacity uncertainty blocks before outbound HTTP.
- Authentication and security headers also apply to early 401/413/429 responses.
- Two API identities cannot share mappings through the same conversation ID.
- Supported files either produce a verified sanitized artifact or return a non-2xx error.
- Tracked-file credential scan, dependency audit, tests, browser smoke, and container build pass in CI.
