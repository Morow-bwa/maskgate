# Provider adapters

Canonical Privacy IR is independent of provider wire schemas. A provider Adapter parses reviewed
input into IR and serializes IR to one provider body. The final wire guard runs after `to_wire()`.

## Runtime-supported paths

| Public ingress | Remote provider | Non-stream | Stream | Exact body test |
|---|---|---:|---:|---:|
| OpenAI Chat Completions | OpenAI-compatible Chat Completions | yes | yes | yes |
| OpenAI Chat Completions | Gemini `generateContent` | yes | yes | yes |
| OpenAI Responses | OpenAI Responses | yes | no (422) | yes |

All built-in transports accept `PrivacyCheckedPayload`; they send its immutable bytes with no
post-check serialization. Application-owned `httpx.AsyncClient` pools have explicit connection
limits, redirects and environment proxies disabled, no cross-request provider cookies, and lifespan
closure. Gemini credentials use `x-goog-api-key`, never URL query parameters.

Strict Chat streaming requires a recognized finish reason for every observed choice. Missing
finish, duplicate indexes within an event, negative/boolean indexes, post-finish data and explicit
provider error events fail without a successful `[DONE]`. Tool IDs/names and arguments are
accumulated before output inspection. Sparse indexes are preserved in client events; history
deliberately selects choice 0. Replay compatibility is explicit: refusal-only output is normalized
to replayable assistant
content, while legacy `function_call`, incomplete/non-object tool arguments and unsupported terminal
states reject before retention. Complete choices may end at transport EOF without an upstream
`[DONE]`; MaskGate emits its own `[DONE]` only after checked finalization and any required commit.

Scoped policy ALLOW provenance is preserved for OpenAI-compatible Chat and the reviewed Responses
text paths. Gemini path translation currently rejects a request containing an ALLOW grant because
that serializer does not yet expose a reviewed source-to-wire provenance map; ordinary tokenized
requests remain supported.

The Responses route is deliberately stateless and non-streaming. It forces `store: false`, rejects
`previous_response_id`, built-in/remote tools, media, and unsupported output item types, and accepts
only local function tools plus the reviewed JSON Schema structured-output subset. Successful
provider objects are validated and projected to `id`, `object`, `status`, and typed `output` before
the output guard. Provider error bodies and unreviewed metadata are discarded.

## Adapter-library status

The following pure Adapters have schema/round-trip tests but are not claimed as complete public
network routes because response conversion, transport authentication, and full stream orchestration
are not all wired:

- Anthropic Messages;
- Gemini Interactions (experimental and opt-in by design).

Gemini Interactions defaults to `store=false`; `previous_interaction_id` requires both storage
authorization and exact-field policy. Legacy Gemini `generateContent` has no `store` field, so the
Adapter omits it.

## Safe subset and fail-closed behavior

Supported text, function definitions, function calls/results, and structured output are typed in
IR. Remote provider-executed tools are disabled. Unsupported media, unknown fields, cross-provider
extensions, unsafe opaque fields, and schema drift block before transport. OpenAI `metadata` and
`user` are the only currently reviewed top-level extensions on the OpenAI-compatible route; all
their strings and object keys are transformed before serialization.

Adding a runtime provider requires: ingress and egress fixtures, response conversion, auth/target
validation, exact checked-body transport tests, output guard coverage, and an updated threat model.
Streaming may be claimed only after typed event parsing and fragmented-field parity tests pass.
