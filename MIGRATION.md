# Migration to the privacy architecture

## Behavior changes

- Default placeholder mode now uses opaque random tokens. Use `semantic_placeholder` only for
  lower-privacy compatibility.
- User-supplied MaskGate token grammar is blocked to prevent token injection and replay.
- `DETECTOR_PROFILE` defaults to `strict`; new validated identifiers and secrets may cause new
  blocks.
- Unknown detected entity types fail closed after legacy-policy migration.
- API clients cannot override the operator's masking mode. Playground override remains local.
- A conversation cannot change masking mode after creation.
- Unknown provider fields/media and unclassified numeric user values may now block instead of
  passing through.
- Strict streaming buffers supported text/tool fields until complete, increasing first-token
  latency.
- Provider-generated PII not authorized by an active mapping is redacted.

## Public values

Replace global public e-mail/domain/person allowlists with a scoped v2 assertion. Compute its digest
with `app.privacy.policy.hash_public_value`, add provenance and expiry, then set `POLICY_V2_FILE`.

## Provider configuration

`LLM_PROVIDER=openai` keeps the OpenAI-compatible Chat route. `LLM_PROVIDER=gemini` converts the
same public request through Canonical IR into Gemini `generateContent`. Other provider Adapters are
library-level until their complete runtime paths are documented in `PROVIDERS.md`.

## Rollback

Do not roll back final-wire checks, opaque-token collision protection, vault isolation, or output
inspection for compatibility. If a formerly accepted structure is blocked, either add a reviewed
typed Adapter path with tests or keep it unsupported.
