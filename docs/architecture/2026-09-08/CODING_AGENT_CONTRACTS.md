# Coding-agent implementation contracts

Date: 2026-09-08. Status: implementation handoff; no tasks below have been implemented by this
architecture-only review. Primary design: [ARCHITECTURE_BLUEPRINT.md](ARCHITECTURE_BLUEPRINT.md).
Rationale: [ADRS.md](ADRS.md).

## Start-of-task protocol

1. Read repository `AGENTS.md`, `docs/agent/README.md`, `ARCHITECTURE.md`, `PROVIDERS.md`, this
   contract and the task's relevant ADR. User instructions override local guidance.
2. Inspect `git status` and the current target files. The architecture baseline was dirty at HEAD
   `102dcc29970c41257832ccf8f38ff0060d21a54d`; do not reset, overwrite or claim ownership of those
   existing changes. Source line references in the blueprint are navigation hints.
3. Run harness context and inspect the source/test map. Establish a baseline when it has changed.
4. Select exactly one bounded task, state its acceptance cases and permitted files. Add a failing
   synthetic behavior regression before fixing a confirmed defect. Do not create a failing test
   merely to mirror a proposed class arrangement.
5. Keep existing routes runnable and preserve provider support. Run quick checks during work and
   the full harness before declaring completion, plus the task-specific boundary checks below.
6. Update implemented-behavior documentation and the module map only for behavior actually changed.
   Report check commands/results and unavailable gates honestly. No commit, push or deployment is
   implied by this design document.

## Non-negotiable invariants

- I1: Exact checked bytes are the only provider body on a built-in runtime transport.
- I2: One PrivacyDetector semantics contract protects ingress, final wire and output; terminal
  capability validation cannot be bypassed by configuration, retries or adapters.
- I3: Unknown structures, malformed outputs, inspection uncertainty and exhausted budgets block
  outbound data or redact/reject output. No permissive fallback after an exception.
- I4: Exceptions are exact-path, bounded and scoped. No exemption for all JSON keys, protocol IDs,
  numeric arrays or globally matching approved strings.
- I5: Only active, owning-principal scope permits authorize restoration. Delete/revoke invalidates
  future restoration and commit; possession of a copied MappingItem list is not sufficient.
- I6: Conversation history is provider-safe and never receives restored client output or raw
  provider accumulator text. New provider PII must not be retained in it.
- I7: One active writer per principal/conversation generation; history and mapping state commit
  together. A stale commit cannot report success or silently disappear.
- I8: Every operation releases leases, reservations, response streams and request mapping
  references on success, expected errors, unexpected exceptions and cancellation.
- I9: Raw originals, credentials, raw prompts, mappings and diagnostic payloads never enter logs,
  telemetry, test reports or durable storage. Fixtures are synthetic only.
- I10: One process, RAM-only vault. No hidden Redis/SQLite/file checkpoint, broker or extra worker
  process introduced as an implementation convenience.
- I11: Runtime support remains OpenAI-compatible Chat, Gemini generateContent and non-stream
  OpenAI Responses subset. Library adapters do not authorize public routes.
- I12: Local media has no provider network capability; irreversible file rendering uses explicit
  policy context and verified bounded volatile raw-input storage in strict mode.

## Dependency and coding rules

Domain depends on value types and inward ports. Infrastructure implements those ports. HTTP routes
translate only. Provider codecs do not own network, state or credentials. Chat and Responses do not
depend on each other's implementation. Bootstrap is the only implementation selector.

Keep comments, documentation and tests in English. Communicate with the user in their language.
Prefer specific DTOs/Protocols and typed errors to `Any`, `hasattr` dispatch and catch-all helpers at
security seams. Use existing local style and Ruff configuration; no unrelated formatter churn.
Place shared error contracts at the inward seam, not in a sibling route module or generic utils.

Keep provider-specific parsing separate from common orchestration. Do not build an abstract plugin
framework, service container, repository-of-repositories, event bus or generalized workflow engine.
Create a new abstraction only when it owns one invariant or removes demonstrated duplication.

Use monotonic clocks for expiry/deadlines and injected clocks for tests. Wall-clock assertion expiry
is explicitly timezone-aware. A lock protects ownership, not authorization by itself. No global
lock is held across network I/O. Avoid raw exception formatting and serialization in errors.

## Task graph and coordination

`T0 -> T1 -> T2 -> T3 -> T4 -> T5 -> T6 -> T7` is the safe default integration order.
Documentation/test planning can proceed separately, but multiple agents must not edit shared
contracts, `main.py`, the same orchestrator or state owner concurrently without an assigned owner.
Do not spawn agents merely because tasks are listed here; delegation still requires the current
user/session's authorization or applicable instructions.

### T0 — Reproduce and freeze the current defects

Objective: convert architecture probes into permanent boundary tests without changing runtime.

Permitted files: `app/tests/test_conversation_vault_lifecycle.py`,
`app/tests/test_chat_orchestrator_fail_closed.py`, `app/tests/test_streaming_privacy.py`, or adjacent
clearly named regression files; relevant test-map entries only.

Required cases:

- Local fake provider emits a synthetic sensitive value absent from the prompt. Client output
  redacts it, retained stream history excludes it, and a safe second turn succeeds.
- Fake clock advances idle TTL while a conversation is locked/leased. A second state must not
  become an independent writer under the same generation. Stale commit is observable.
- Inject a transformation exception after streaming state acquisition but before iteration.
  Subsequent same-conversation work remains possible; mapping/store reservations are empty.
- An abandoned/pre-start response and cancellation at each lifecycle boundary do not leak ownership.

Validation: demonstrate the first three tests fail on the inspected defect, not because of fixture
schema mistakes. The exploratory empty-model probe did NOT reproduce a lock leak and must not be
reported as a proven exploit. Use fake-clock/barrier tests, no long sleeps and no external network.

Exit: short evidence receipt with failing test names and expected invariant; coordinate integration
with T1/T2 so intentionally failing tests are not presented as a completed runnable release.

### T1 — Correct streaming history and finalization

Dependencies: T0 output regression.

Permitted files: `app/proxy/streaming.py`, output-related portions of
`app/chat/orchestrator.py`, `app/privacy/output_guard.py`, `app/privacy/ir/stream.py`, adjacent
stream/output tests. Add a small output DTO/module only when used by this change.

Deliverable: a safe-history projection from finalized output; retain the client projection
separately. No raw `provider_text()` string may be accepted by the history commit path.
Preserve structured assistant tool/refusal state and semantic choice/tool identity. If multiple
choices are supported, select the documented history choice deliberately; do not concatenate them.

Required validation:

- New provider PII absent from client and retained history; next turn passes the wire guard.
- Existing authorized token restoration works while provider-safe history retains tokens.
- Tool arguments split across all relevant boundaries, refusal and structured outputs preserve
  their intended fields. Sparse/reordered choice/tool indexes never mix buffers.
- Missing finish/terminal conditions and invalid envelopes fail without successful completion.
- No finish marker reaches the client before buffered final content/commit semantics permit it.
- Existing exact-byte and streaming regression suite passes.

Forbidden: relaxing strict buffering, replacing an unsafe output with the original, enabling new
provider support, broad refactoring of request-side policy logic.

### T2 — Make request and conversation ownership explicit

Dependencies: T0 lifecycle regressions; T1 finalization interface.

Permitted files: `app/storage/conversation_store.py`, `app/storage/mapping_store.py`,
`app/privacy/vault.py`, lifecycle portions of `app/chat/orchestrator.py`, `app/main.py` lifespan,
new `app/application/conversations.py`/contracts when necessary, principal/lifecycle tests.

Deliverable: one operation context owns acquired state from setup through stream completion and
teardown. Introduce generation/revision and lease validity. Idle expiry does not detach leased
state. Delete/revoke prevents later restore and commit; commit results are explicit.

Required validation:

- Same owner/ID has one writer; another owner with the same ID remains independent.
- Fake-clock expiry under active work cannot create a concurrent writer; bounded turn timeout
  eventually releases state. Delete and recreate creates a new generation.
- Barrier-controlled deletion during provider I/O prevents subsequent client restoration and commit.
- Cancellation before/after acquiring state, before generator startup, during iteration and after
  finalization releases resources exactly once. Fault injection covers non-policy exceptions.
- Commit publishes history/mappings atomically, prunes references, and distinguishes stale/revoked.
- Request-scoped mappings disappear at teardown; no persistent copy is added for recovery.

Compatibility decision: document late delete, expired sessions, mode conflict and conflicting
body/header IDs. Validate structurally invalid requests before taking a lease.

Forbidden: global lock across provider I/O, durable checkpoints, a second ownership registry,
silent stale-commit success, restoration authorized solely by a MappingItem list.

### T3 — Add bounded admission, deadlines and transport lifecycle

Dependencies: T2 lifecycle.

Permitted files: `app/config.py`, `app/security.py`, application budget/deadline contracts,
`app/proxy/llm_client.py`, `app/proxy/gemini_client.py`, `app/main.py`/bootstrap lifespan,
bounded stream readers, resource/transport tests, deployment limits documentation.

Deliverable: global/principal/operation reservations and absolute deadlines, with bounded lock
wait and stream duration. Configure reusable clients and explicit connection limits. The runtime
port accepts only checked payloads; choose an explicit compatibility adapter for direct library calls.

Required validation:

- Aggregate capacity exhaustion rejects before provider call/expensive allocation.
- Every fail/cancel path restores reservation counters; simultaneous tenants cannot exhaust all
  capacity beyond the configured admission policy.
- Slow chunks under the idle timeout still stop at the total deadline; newline-free streams remain
  bounded. Decoded work, structure depth and field count are bounded in addition to raw bytes.
- Exact content equals checked body with reused connections. No provider Set-Cookie, client header,
  redirect or environment proxy configuration creates an unreviewed data/credential channel.
- Pool closes on shutdown. Draining rejects new work and terminates remaining work within limits.
- Report measured workload/RSS envelope; do not claim a universal requests-per-second capacity.

Forbidden: automatic generation retries/failover, queueing unlimited raw bodies, weakening the
64 KiB/four-layer guard limits, increasing Uvicorn worker count.

### T4 — Preserve policy context and enforceable obligations

Dependencies: T2 scope identity and T3 budgets.

Permitted files: `app/privacy/runtime.py`, `app/privacy/policy/`, shared application context,
request transformation in Chat/Responses, `app/privacy/pipeline.py`, scoped grant integration in
`wire.py`, provider codec provenance fields, policy/adapter/exact-wire tests and policy docs.

Deliverable: explicit source/canonical/wire path semantics and scoped approvals tied to principal,
provider/direction/purpose, policy revision and expiry. The policy issuer and terminal grant verifier
have separate responsibilities. Validate mandatory obligations against implemented capabilities.

Required validation:

- The same configured logical rule reaches the intended field on Chat and Responses without
  accidental broadening. Serializer movement must preserve or reject approval provenance.
- A grant valid for one path/context does not authorize another. Expired/wrong-owner/wrong-provider
  grants and historical expired approvals reject before HTTP.
- Public assertions do not override an applicable block/review decision. Legacy compatibility cases
  are explicit. Update the misleading policy example precedence comment with this change.
- Unsupported mandatory obligations fail config load; informational annotations do not masquerade
  as completed audit/alert/vault actions.
- Exact-wire rejection and compatibility cases pass on all supported provider paths.

Forbidden: global approved-value exemption, logging matching value hashes or decision reasons from
untrusted sources, inventing a review queue, automatic emails/alerts to people.

### T5 — Align local media policy and volatile upload storage

Dependencies: T3 admission and T4 policy contract.

Permitted files: `app/media/`, media HTTP wiring, upload boundary in `app/security.py`, relevant
settings/deployment profile, media tests/docs. Shared policy contracts require coordination with T4.

Deliverable: trusted MediaContext includes the verified principal/application/purpose and local
file route semantics. The renderer applies irreversible policy decisions. Strict input storage is
bounded RAM or verified volatile spool, including multipart parsing before handler execution.

Required validation:

- Tenant-scoped policy differences are applied to media deliberately; a local route does not
  pretend to be a remote-provider authorization.
- Above-threshold synthetic uploads cannot spill originals to ordinary persistent OS temp storage
  in strict mode. Test parse failure, cancellation, full download and output-size rejection.
- Archive expansion, XML/relationship allowlists, PDF rasterization, image metadata rebuild and
  missing dependency behavior remain fail closed. No fallback to original file.
- Admission bounds queued uploads as well as active OCR threads. State clearly whether native
  work can be stopped; do not claim thread cancellation kills native execution.

Forbidden: provider upload, execution-time model downloads, persisting raw files to simplify jobs,
silent relaxation of strict storage guarantees on Windows.

### T6 — Extract modules and enforce dependency rules

Dependencies: stable behavior/contracts from T1-T5.

Permitted files: `app/application/`, `app/api/`, `app/bootstrap.py`, existing Chat/Responses routes
and orchestrators, compatibility exports in `masking`/`policies`, provider codecs/transports,
architecture tests, `docs/agent/project.json`.

Deliverable: small format-specific application services share context, lifecycle, finalization and
error contracts. Domain depends inward; routes no longer construct business behavior. Remove
Responses-to-Chat import and runtime duck-typing. Keep `app.main:app` and public imports required by
documented examples runnable through explicit compatibility exports during migration.

Required validation: import/AST tests enforce prohibited edges; all existing supported-route
fixtures and exact transport tests pass; no library-only adapter becomes a runtime provider.
One extraction per reviewable change. Update the source/test map as files actually move.

Forbidden: moving all directories at once, universal provider orchestration framework, removing
compatibility before replacing consumers, unrelated frontend or dependency upgrades.

### T7 — Complete operational evidence and release handoff

Dependencies: T1-T6.

Permitted files: `app/observability/`, `app/logging_config.py`, fixed-code instrumentation at
application/guard/state seams, health/lifespan endpoints, harness/CI checks and relevant deployment,
provider, architecture and performance documents.

Deliverable: counters/histograms are actually emitted for terminal/state paths; protected bounded
export does not expose content. Readiness means local service readiness, not provider success.
Publish supported deployment/workload limits and remaining untested areas.

Required validation: safe logging/metrics adversarial tests, no high-cardinality labels, no diagnostic
payload in telemetry, full harness, representative load/fault tests, applicable frontend build and
credential-free browser smoke, affected lock audits, Linux Docker smoke and remote CI. If a tool or
environment is unavailable, mark that release gate pending. Do not fabricate a pass from an old report.

Forbidden: broad public metrics access, body capture, raw exception/URL tracing, durable audit claims
without a separate design, treating synthetic corpus scores as real-world detection rates.

## Review and completion template

Each coding-agent handoff must contain:

- Task ID, exact baseline including pre-existing changes, and scope of files actually modified.
- Concrete before/after behavior and invariant protected.
- Contracts or compatibility decisions changed, with updated support/docs links.
- Reproduction and regression results; exact transport/zero-send evidence when applicable.
- Commands actually executed, measured outcomes and pending environment/provider gates.
- Remaining risks and rollback behavior; no claim that local tests prove absence of vulnerabilities.

Stop dependent implementation and report the conflict if it requires new persistence, a new network
trust boundary, broader restoration, weaker inspection, new runtime provider support or an
unresolved ownership contradiction. Continue independent authorized checks. Routine implementation
choices within these contracts do not require repeated permission requests.
