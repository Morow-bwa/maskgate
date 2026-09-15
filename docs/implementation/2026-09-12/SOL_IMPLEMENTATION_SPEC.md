# MaskGate implementation specification for ChatGPT 5.6 Sol

Date: 2026-09-12. Owner: project maintainer. Target: the local working tree, not GitHub.

## 1. Assignment and completion contract

Implement the remaining important privacy, lifecycle, resource and operational fixes in:

`<repository root>`

This is an implementation assignment: inspect, reproduce, fix, test and update documentation.
Do not stop after producing another architecture plan. Work through the ordered milestones below.
Report every unfinished milestone explicitly. Passing tests do not mean all milestones are complete.
Do not promise perfect PII detection or that all possible vulnerabilities have been eliminated.

Use ChatGPT 5.6 Sol. Communicate with the maintainer in Russian; repository code, comments, tests and docs
remain English. Work directly on this checkout. No GitHub clone, reset, dependency refresh, commit,
push, merge, deployment or live provider call is implied. Routine reversible fixes and synthetic
local checks are authorized. Ask only for a necessary missing decision or external permission.

Read `AGENTS.md`, `docs/agent/README.md`, `ARCHITECTURE.md`, `PROVIDERS.md` and the September 8
architecture package. This specification updates that package's implementation status, not its
security invariants. Baseline HEAD: `102dcc29970c41257832ccf8f38ff0060d21a54d`; branch:
`codex/phase2-privacy-consistency`. The working tree is dirty: HEAD alone does not identify it.
Record status and inspect diffs before editing. Preserve all existing changes. Do not restore files
from HEAD or attribute all existing differences to this task. Implement one reviewable milestone
at a time and run its checks before proceeding to dependent work.

## 2. September 12 implementation already present

Inspect and build on these changes instead of repeating the old blueprint:

- `app/proxy/streaming.py`: `FinalizedStream` separates client events and provider-safe history;
  choice/tool indexes are semantic, including sparse/reordered indexes; tool metadata is assembled
  before inspection; each observed choice needs a finish reason; only choice 0 enters history.
  Raw `provider_text()` was removed. Explicit errors and post-finish data fail closed.
- `app/chat/orchestrator.py`: uses finalization, attempts history commit, then emits checked content,
  finish markers and `[DONE]`. Raw provider text is no longer committed by streaming.
- `app/tests/test_streaming_history_finalization.py`: tests new provider PII, second text turn,
  completion order, restoration/history separation, semantic indexes, structured fields and aborts.
  The first two regressions failed on the pre-fix implementation.
- Existing mock streams now contain proper finish events and complete tool metadata. Privacy
  assertions remain. The quick harness/module map include the new regression file.

This is a substantial part of T1, not completion of T0-T7. Commit still silently ignores detached
state; deletion does not revoke copied mappings; setup/cancellation ownership remains unsafe.
Refusal/legacy function fields are retained, but replay through the request adapter needs an explicit
compatibility decision. The finalizer does not enable new request formats.

September 6 encoded-key/budget hardening already exists locally. Do not claim those historical
defects remain without a fresh failing regression. See `REVIEW_AND_EVIDENCE.md` for this run's receipt.

## 3. Priorities and evidence status

| ID | Priority | September 12 evidence/status | Required result |
|---|---|---|---|
| LIF-1 | P0 | Fake clock expired locked state and allowed a distinct state for the same key | Active ownership survives idle expiry; one writer |
| LIF-2 | P0 | Detached-state commit returned normally without publishing history | Explicit stale/revoked commit failure |
| LIF-3 | P0 | Injected transform ValueError leaked stream lock; zero upstream calls | One owner covers setup through teardown |
| LIF-4 | P0 | Static: restoration takes copied mapping lists without live scope validation | Delete revokes future restoration and commit |
| STR-1 | P1 | Unsafe history and early finish reproduced and fixed | Preserve fixes; close structured replay/terminal gaps |
| RES-1 | P1 | Static: local vault limits/rate limits do not bound aggregate in-flight state | Global/principal/operation budgets |
| RES-2 | P1 | Static: phase timeout, unbounded lock wait, per-call clients | Total deadlines and transport lifecycle |
| POL-1 | P1 | Static: approvals become original-value sets without path/expiry evidence | Scoped serialization/history provenance |
| POL-2 | P1 | Static: obligation strings are returned, not enforced | Mandatory obligations vs annotations |
| MED-1 | P1 | Static: local media lacks principal/purpose and uses legacy policy | Explicit contextual media decisions |
| MED-2 | P1 | Installed multipart parser spools at 1 MiB; volatile Windows backing unverified | No raw persistent spool in strict mode |
| OPS-1 | P2 | Static: mixed composition and limited terminal/state instrumentation | Dependency boundaries and operational evidence |

P0 is implementation priority, not a claim of a critical remote exploit. LIF-3 is fault injection,
not proof a normal request triggers ValueError. Static capacity/provenance/media concerns need
regression evidence before claims of an OOM, cross-tenant disclosure or public policy bypass.

## 4. Non-negotiable invariants

1. Built-in transports send precisely `PrivacyCheckedPayload.body` after final serialization.
2. Ingress, final wire and output preserve the same detector capability and semantics contract.
3. Unknown structures, inspection errors and exhausted budgets fail closed. Keep the 64 KiB/four
   decoded-layer limits. Never exempt every JSON key, ID or matching approved string.
4. Originals stay in authorized volatile scopes; no originals in provider-safe history, logs,
   metrics, durable reports or fixtures. All test data is synthetic; all upstreams are local mocks.
5. One principal/conversation generation has one writer; history and mappings publish atomically.
6. Restoration requires a valid owning scope, not possession of tokens or mapping lists.
7. Each lease, reservation, upstream stream and request mapping has one owner and bounded teardown.
8. Keep one process and RAM-only vault. No Redis, database, broker, persistent checkpoint or extra
   worker process as a shortcut. No automatic generation retry/failover.
9. Preserve runtime OpenAI Chat, Gemini generateContent and the reviewed non-stream OpenAI Responses
   subset. Do not enable remote tools, Responses streaming, Anthropic or Gemini Interactions.

## 5. Milestone A: lifecycle ownership and revocation

Primary files: conversation/mapping stores, privacy vault, lifecycle portions of Chat orchestrator,
main lifespan, adjacent lifecycle/principal tests. Add a small operation/context contract as needed.

First add failing permanent regressions for LIF-1 to LIF-3 using fake monotonic clocks and async
barriers. A single ownership context must cover acquisition, preparation, provider I/O, finalization,
commit and teardown. An unstarted generator's finally does not release an already acquired lock;
background response callbacks, GC and TTL are not sufficient ownership mechanisms.

Add generation/revision and a revocable lease/permit. Idle expiry cannot detach an active lease.
Bound the whole operation so abandoned work eventually ends. Revalidate after waiting for a lock.
Delete/recreate must produce a different generation. Validate requests/mode and conflicting body/
header conversation IDs before taking ownership; define compatibility behavior explicitly.

Commit must return an explicit result or raise a typed error for stale/revoked state. Validate before
publishing history/mappings or pruning shared state; publish both atomically. Never report success
when commit silently disappeared. Do not hold global locks across provider I/O or client sends.

Delete/revoke invalidates permits for the old generation. Check scope immediately before restoration
and commit/publication. Define a linearization point: bytes already sent cannot be recalled, but
deletion before authorization must prevent subsequent restoration. A copied MappingItem list is
not sufficient authorization. Cover request-scoped restoration too.

Acceptance:

- One writer for same owner/ID during cleanup and wait; different owners remain independent.
- Idle expiry works; leased expiry cannot create a second writer; timeout releases ownership.
- Delete during blocked I/O, recreate same ID, resume old call: no old original restored, no old
  commit, explicit failure, new generation unchanged.
- Cancel before/after acquire, before iterator startup, during iteration/finalization and after
  commit. Cleanup is exactly once; next work succeeds; mapping/reservation counts return to baseline.
- Inject exceptions from clone, transform, prepare, mapping put, response construction, output and
  commit. Check locks, mappings and upstream stream closure, not only response status.
- Document commit-before-delivery semantics on client disconnect. RAM commit and network delivery
  are not atomic; do not promise they are.

## 6. Milestone B: streaming and replay completion

Build on the new finalizer. Validate through public routes and both transports, preserving exact
checked bytes. Retained state must be checked for both privacy and supported next-turn structure.

Acceptance:

- Test every split boundary of tokens, provider PII, JSON tool arguments and IDs/names.
- Reordered/sparse choices and tools keep identity. Duplicate/negative/boolean indexes reject.
  No filler choices/tool calls. Multiple choices reach client; history selects semantic choice 0.
  Define/test no-choice-0 behavior deliberately.
- New PII never enters history; active originals restore only in authorized client fields. Run a
  second mocked turn, including tool results referencing retained IDs.
- Decide safe replay for refusal/legacy function_call: explicit supported normalization or rejection
  before successful retention. Do not silently discard fields or globally relax unknown-field rules.
- Validate malformed/partial JSON arguments and length termination before they poison history.
  Test redaction that replaces an entire arguments string and metadata redaction/collision behavior.
- Empty stream, missing finish, unsupported reason, duplicate finish, provider error, late data and
  EOF: test actual SSE bytes. Distinguish per-choice finish from transport DONE/Gemini termination;
  define accepted transport EOF behavior, including missing DONE after otherwise complete choices.
- No finish/DONE before checked content and required successful commit. Inspection failure returns
  fixed public errors, never original provider content or raw exception strings.

## 7. Milestone C: budgets, deadlines and reusable transports

Primary files: config, security/admission, stores, Chat/Responses, proxy clients, bounded readers,
lifespan. Account for global and per-principal counts/bytes, conversation originals/history, session
clones, mapping copies, buffered output and queued uploads. Reserve before expensive allocation or
transformation; adjust bounded accounting as needed. Capacity rejects before provider calls.
Rate limiting alone is not admission. Never queue unlimited raw bodies.

Use an absolute monotonic deadline across admission, lock wait, processing, provider and stream.
Keep phase/idle HTTP timeouts too. Bound depth, field count and decoded work as well as bytes.
Document limits of interrupting synchronous or native work.

Manage reusable AsyncClient pools through lifespan with explicit limits/closure, disabled redirects
and deliberate environment-proxy behavior. Audit cookies: Set-Cookie must not create unintended
cross-request state. Client Authorization/unreviewed headers must not reach provider requests.

Acceptance: exact MockTransport content equals checked body; zero network calls on rejection; all
reservations restored after errors/cancellation; slow chunks under idle timeout still hit total
deadline; principal isolation under load; bounded shutdown/draining; pool closes. Measure a bounded
synthetic workload and peak RSS on this 16 GB Windows PC, with actual concurrency/payload conditions.
Do not claim universal RPS, multi-worker safety or an OOM fix without measurements.

## 8. Milestone D: contextual approvals and obligations

Primary files: privacy runtime/policy, pipeline/wire, Chat/Responses transforms, codec provenance,
policy docs/tests. Replace value-only approvals with trusted evidence binding principal, route,
provider, direction, purpose, source/canonical/wire location, policy revision and expiry. Retokenize
or reject if translation cannot preserve evidence. Historical approvals must not outlive validity.

Acceptance: same logical rule behaves intentionally in Chat/Responses; relocated field, wrong owner/
provider, expired grant and an approved string copied into a disallowed field reject with zero HTTP
calls. Document schema migrations and explicit legacy compatibility. Preserve detector consistency.

Separate informational annotations from enforceable mandatory obligations; reject unsupported
mandatory obligations at config load. Returning `audit_decision` or `alert_security_owner` metadata
does not execute it. Do not send automated messages to people. Preserve deny/review precedence,
correct the misleading example comment, and test priority ordering including higher-priority ALLOW
vs lower-priority BLOCK instead of making an undocumented precedence change.

## 9. Milestone E: local media and volatile raw input

Primary files: media routes/sanitizer/redactor, HTTP upload boundary, settings/deployment docs.
Pass trusted principal/application/purpose/local route/policy revision in MediaContext. Apply
irreversible contextual decisions. A local renderer is not a remote provider and must not acquire
upload/network/model-download capability.

Establish strict storage before multipart parsing; a handler-only fix cannot prevent prior spooling.
Use bounded RAM or verified volatile storage, never a silent Windows persistent-temp fallback.
Bound size/count/admission while receiving and queued files before OCR capacity acquisition.

Acceptance: synthetic upload above spool threshold, parse failure, cancellation, full download and
output limit; verify no ordinary persistent spool in strict mode. Test different tenant policies on
the same synthetic file. Preserve ZIP/XML/PDF/image allowlists, expansion limits, metadata rebuild
and missing-dependency rejection; never return the original on failure. Cancelling a coroutine does
not kill native OCR; document and test the actual execution bound.

## 10. Milestone F: module boundaries and operational evidence

After A-E stabilize, extract small API/application/bootstrap responsibilities one at a time.
Remove Responses-to-Chat error-helper dependency through an inward shared contract. Keep provider
codecs/format orchestration distinct. No universal framework, event bus or service container.
Preserve app.main:app and documented imports. Add meaningful import/AST dependency checks and update
the module map when files move.

Emit actual wire/output/state/admission counters and bounded timing distributions. Fixed labels only:
no arbitrary models/tenants, values, prompts, paths or raw exceptions. Protect/bound the exporter.
Readiness reflects local readiness/admission/draining, not unmeasured provider connectivity.
Refresh README/status/security/support docs to match implemented behavior.

Run a separate adversarial review phase over final diffs and lifecycle/transport tests. Do not call
the implementer's own reread an independent audit. Preserve remaining limitations explicitly.

## 11. Validation and release boundaries

For each milestone: reproduce, implement, focused tests, quick harness, diff review, evidence.
Keep compatibility cases beside rejection cases. Do not delete assertions, weaken privacy guards,
lower coverage, xfail regressions or change a protocol fixture solely to hide a real failure.

```powershell
.\scripts\check.ps1 -Command context
.\scripts\check.ps1 -Command doctor
.\scripts\check.ps1 -Quick
.\scripts\check.ps1
git diff --check
```

Use the wrapper's interpreter selection; do not reinstall the environment as a side effect. On
September 12 the venv worked in authorized test execution, while restricted execution failed; do
not infer a broken installation from the restricted failure alone.

Audit changed dependencies and verify lockfiles if touched. For frontend edits, build and run local
credential-free browser smoke. For release, separately run Linux Docker build/smoke and applicable
browser/remote CI gates. Docker was unavailable on September 12; do not fabricate a pass or install
Docker automatically. Live provider calls, uploads and publishing are separate permissions.

Record final test counts/coverage/receipts, not the historical 404-test result. The 598-case synthetic
corpus is regression evidence, not a measured real-world detection rate.

## 12. Required final handoff

Provide a Russian user summary and an English evidence document with:

- Each ID: fixed / verified already fixed / reproduced unresolved / hypothesis / untested.
- Baseline and files changed by this task, separated from pre-existing modifications.
- Before/after behavior, changed contracts, compatibility decisions and rollback scope.
- Commands/test names, counts/coverage, exact-wire/zero-send checks and receipt paths.
- Measured resource envelope, remaining Windows/Linux/provider differences and unavailable gates.
- Remaining risks; no general production-ready claim while P0/P1 requirements remain open.

Completion requires implementation and evidence for every accepted milestone, or a clearly reported
external blocker. Do not silently reduce the assignment to the first easy milestone.
