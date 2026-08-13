# Threat model

## Scope and trust assumptions

MaskGate protects documented sensitive-data surfaces when sending requests to a remote LLM. The
trusted computing base is the MaskGate host, process/runtime, local detector/media dependencies,
configuration, and operator-controlled TLS/egress path. The client, uploaded files, provider, and
all provider responses are untrusted.

## Assets

- inbound prompts, tool data, files, and conversation mappings;
- MaskGate and provider credentials;
- provider-safe conversation history and exact outbound bodies;
- tenant isolation, policy integrity, and process availability.

## Trust boundaries

1. Client -> HTTP application: auth, trusted host, rate/body limits, principal resolution.
2. Request -> privacy runtime: bounded canonicalization, local ensemble, risk and contextual policy.
3. Canonical IR -> provider Adapter: typed supported fields; unknown/remote/opaque surfaces block.
4. Adapter -> remote provider: exact body passes `FinalWirePrivacyGuard`, becomes a sealed payload,
   and is sent unchanged.
5. Provider -> output guard: bounded JSON/SSE, response/event validation, PII inspection, authorized
   restoration.
6. Upload -> media pipeline: hostile archives/documents/images enter bounded parsers and local
   verification.
7. Process memory -> host: originals exist temporarily in request buffers and the RAM vault.

## Attackers and abuse cases

- unauthenticated clients and authenticated tenants attempting capacity exhaustion;
- one tenant reusing another tenant's conversation ID;
- prompts hiding data in object keys, metadata, tool schemas/arguments, nested JSON, Unicode
  evasions, base64/hex/escapes, numeric scalars, or fake MaskGate tokens;
- Adapter/schema drift, target manipulation, remote tools, server-side provider storage, and
  unsupported media;
- providers returning reordered/unknown tokens, new PII, malformed JSON/SSE, fragmented tool data,
  or oversized responses;
- archives with traversal, duplicate entries, expansion bombs, active relationships, macros,
  embedded objects, metadata, invisible text, or difficult OCR/face inputs;
- accidental secret publication through source, Git history, logs, metrics, or debug responses.

## Security properties

- Principal context contains only pseudonymous credential-derived identifiers. Vault and
  conversation keys include that namespace.
- Privacy decisions can use tenant/application/route/provider/model/purpose/path/role/confidence/
  risk/recognizer/token scope. Missing v2 matches fail closed.
- Public-data assertions are exact, scoped, expiring, provenanced, and cannot override explicit
  block/review rules.
- Built-in transports cannot accept arbitrary dictionaries from the application path. Direct
  library dictionary calls still run a local strict final guard.
- Provider-safe history retains tool calls/results with opaque tokens; rehydrated originals are
  returned to the client only.
- Media is never attached to a provider request automatically. Unsupported or unverifiable formats
  block.
- Production startup requires auth, trusted hosts, HTTPS provider URL, and disabled Playground/
  debug endpoints.

## Residual and out-of-scope risk

- Detection/OCR/face false negatives and semantic re-identification.
- Host compromise, memory inspection, swap, core dumps, and dependency compromise.
- TLS termination and network policy misconfiguration by the operator.
- Availability attacks within configured CPU/memory/concurrency limits.
- Multi-worker/shared-vault consistency and all undocumented provider/media surfaces.
- Regulatory certification or legal conclusions.

## Acceptance criteria

- Mock providers observe exact post-Adapter checked bytes and no known fixture original.
- Unknown structures, detector/policy/Adapter errors, unsupported media, malformed output, and
  uncertainty block before remote transport or before client success.
- Reversible replacements are collision-free and token injection cannot authorize restoration.
- Same conversation ID under two credentials creates isolated state.
- Trim/expiry/delete remove mappings no longer referenced by retained provider-safe history.
- Red-team attempts raw provider leakage, incorrect rehydration, cross-principal access, streaming/
  tool bypass, stale retention, logging leakage, and hostile files before release.
