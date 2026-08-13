# Provider adapters

Canonical Privacy IR is independent of provider wire schemas. A provider Adapter parses reviewed
input into IR and serializes IR to one provider body. The final wire guard runs after `to_wire()`.

## Runtime-supported paths

| Public ingress | Remote provider | Non-stream | Stream | Exact body test |
|---|---|---:|---:|---:|
| OpenAI Chat Completions | OpenAI-compatible Chat Completions | yes | yes | yes |
| OpenAI Chat Completions | Gemini `generateContent` | yes | yes | yes |

Both built-in transports accept `PrivacyCheckedPayload`; they send its immutable bytes with no
post-check serialization. Gemini credentials use `x-goog-api-key`, never URL query parameters.

## Adapter-library status

The following pure Adapters have schema/round-trip tests but are not claimed as complete public
network routes because response conversion, transport authentication, and full stream orchestration
are not all wired:

- OpenAI Responses;
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

Adding a runtime provider requires: ingress and egress fixtures, response conversion, typed stream
events, auth/target validation, exact checked-body transport tests, output guard coverage, and an
updated threat model.
