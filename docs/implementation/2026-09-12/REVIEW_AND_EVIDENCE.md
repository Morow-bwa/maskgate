# Local implementation review and evidence

Dates: 2026-09-12 through 2026-09-13. Scope: the local MaskGate checkout, not GitHub or a live
provider deployment.

## Baseline and ownership

Root: local MaskGate repository checkout.
Branch: `codex/phase2-privacy-consistency`. Baseline HEAD:
`102dcc29970c41257832ccf8f38ff0060d21a54d`.

The working tree was already dirty. Existing terminal encoding work and streaming fixes were
preserved. In particular, the checked-wire/output changes, `encoded.py`, streaming finalizer,
streaming tests, harness, architecture package and related documentation were not reset or replaced.
The diff from HEAD therefore contains both pre-existing work and this implementation. No commit,
reset, checkout, dependency refresh, network provider call, push, deployment or live upload was
performed.

This implementation added or materially changed lifecycle/store ownership, resource admission,
deadlines, scoped approvals, policy obligation semantics, media context/storage boundaries,
transport pools, module boundaries, metrics, tests and documentation. Rollback must be a selective
revert of those increments, never a reset to the baseline commit.

## Issue status

| ID | Status | Implemented and verified behavior |
|---|---|---|
| LIF-1 | Fixed | Active/waiting leases survive idle cleanup; one writer per owner/conversation generation; bounded lock wait |
| LIF-2 | Fixed | Generation/revision validation and typed stale/revoked commit failures replace silent stale commit |
| LIF-3 | Fixed | Ownership spans setup, provider I/O, finalization, commit and teardown; setup/cancellation regressions release state |
| LIF-4 | Fixed | Delete/recreate revokes the old generation and live request/conversation permits are checked immediately before restore, emit and commit |
| STR-1 | Fixed | Existing streaming repairs were preserved; split fields, semantic indexes, replay, terminal states and provider-safe history were completed |
| RES-1 | Fixed | Global/principal/operation admission and retained conversation byte accounting are bounded; retained-state capacity is reserved before provider I/O |
| RES-2 | Fixed | One total operation deadline covers response streaming; provider clients are pooled, bounded and closed during lifespan shutdown |
| POL-1 | Fixed for supported mappings | Request-local approvals bind owner, application, route, provider, direction, purpose, source/wire paths, policy revision, expiry and decision ID |
| POL-2 | Fixed | Informational annotations are separate; unsupported non-empty mandatory obligations reject policy load |
| MED-1 | Fixed | Local media receives trusted principal/application/purpose/jurisdiction/route/policy revision and applies irreversible contextual decisions |
| MED-2 | Fixed within the local HTTP contract | Multipart spool threshold is configured before route parsing above the accepted body bound; strict mode rejects a rolled file |
| OPS-1 | Fixed with stated review limit | Shared inward error contract, transport capabilities, AST boundaries, readiness and fixed-label aggregate metrics were added |

`POL-1` deliberately rejects scoped approvals for provider translations whose reviewed path
provenance is unavailable. Gemini requests with such approvals fail closed; this is not a claim of
new provider support. Runtime support remains OpenAI-compatible Chat, Gemini generateContent through
the existing Chat ingress, and the reviewed non-stream OpenAI Responses subset.

## Behavior and compatibility decisions

- Conversation IDs and masking mode conflicts are validated before ownership. Delete/recreate uses
  a new generation. Commit publishes history and vault state atomically or raises a typed error.
- A conversation publish reservation conservatively includes bounded retained messages, the current
  vault and the configured maximum provider response. It is consumed by commit or released once by
  teardown. Capacity rejection occurs before the provider call.
- RAM commit precedes final successful streaming events and `[DONE]`. Network delivery and RAM
  commit cannot be atomic: a disconnect after commit may leave committed history the client did not
  fully receive.
- Streaming uses declared choice/tool indexes. All choices can reach the client, but only semantic
  choice 0 is eligible for conversation replay. A conversation stream without choice 0 rejects;
  a request-scoped stream remains supported. Refusal is normalized; legacy `function_call` rejects
  before retention. Tool arguments must finish as a JSON object.
- Provider EOF is accepted only after every observed choice has a valid finish. Empty/truncated,
  duplicate/unsupported finish, invalid indexes, provider errors and late data fail closed. No
  successful finish or `[DONE]` is emitted before checked content and required commit.
- Public assertions do not create value-wide exceptions. Historical request messages are sanitized
  before commit, so an expired ALLOW grant is not retained as a raw original.
- Legacy policy `obligations` remains an informational alias for migration. New files use
  `annotations`; `mandatory_obligations` is rejected until a real executor exists.
- Strict media accepts exactly one file, reads one byte beyond the file limit, bounds sanitized
  output, preserves existing ZIP/XML/PDF/image checks and never returns the original on failure.
  Native OCR already running in a worker cannot be killed by coroutine cancellation; concurrency is
  bounded by `MEDIA_MAX_CONCURRENCY`.
- Built-in HTTP clients use reusable pools with explicit limits, no redirects, no environment proxy
  inheritance and no response-cookie reuse. Every response and lifespan client is closed.

## Tests and evidence

The final current-tree command was:

```powershell
.\scripts\check.ps1
```

Result: PASS, 476 tests, 84.59% branch-aware coverage (required 81.8%), strict synthetic detection
corpus 598 cases with zero reported false positives/negatives, Ruff PASS and repository credential
pattern scan PASS.

Final receipt:
`output/harness/55557ac760aa42fdba6d433b38e0b60d/report.json`.

Focused evidence executed while implementing:

- lifecycle/resource/fail-closed group: 62 tests PASS;
- media security, including above-spool upload, parse failure, tenant context, input/output limit,
  cancellation and native-worker deadline: 16 tests PASS;
- resource/metric regression: 7 tests PASS;
- scoped approvals, exact-wire/zero-send, Chat/Responses, provider pool and streaming suites were
  included in the final full run;
- `git diff --check`: PASS (Git reported only existing line-ending conversion warnings).

The exact-wire tests use `httpx.MockTransport` and assert that provider bytes equal the sealed
`PrivacyCheckedPayload.body`. Rejection cases assert the transport was not called. Streaming tests
cover sensitive values and tool IDs/names across every split boundary and actual SSE EOF bytes.

One earlier quick receipt (`c7334860a74047cca319a0cd64eb00a3`) had passing tests but failed lint
because the new standalone measurement script bootstraps the repository import path. The imports
were marked as intentional bootstrap imports; both targeted Ruff and the final full lint passed.
An earlier full run also exposed readiness/API compatibility regressions; they were corrected before
the final receipt and are not counted as passes.

## Measured resource envelope

`scripts/measure_resources.py` ran a credential-free local mock workload on this 16 GB Windows 11
PC: 12 requests, concurrency 4, 64 KiB message per request. Elapsed time was 2.858 seconds. Sampled
process RSS rose from 68,784,128 to 81,596,416 bytes (12,812,288-byte delta). The final admission
snapshot contained zero active operations and zero reserved bytes. This is one bounded sample, not
an RPS target, multi-worker result or universal OOM claim.

## Separate adversarial reread

A separate final-diff reread covered lifecycle revocation/release, reservation accounting,
checked-byte transport, pool closure, scoped approval translation, output metrics and media
cancellation. It found and corrected two issues before the final harness: conversation retained
capacity could reject after provider I/O, and an output exception was mislabeled as a redaction.

This reread was performed by the implementer. It is not an independent security audit and is not
presented as one.

## Remaining and unverified

- No independent second-reviewer/adversarial audit was performed.
- Docker/Linux build and smoke were unavailable because Docker is not installed on this host.
- Live OpenAI-compatible/Gemini calls, provider-specific streaming behavior, remote CI and deployment
  were not run. Local mocks cannot establish live compatibility.
- No frontend files or dependencies changed in this implementation, so frontend build/browser smoke
  and dependency/lockfile audits were not rerun.
- The fault suite covers setup transform failure, blocked provider I/O with deletion, lock-wait
  cancellation, provider/output/commit failures and stream teardown. It does not individually
  monkeypatch every named internal statement such as `deepcopy` or response-object construction.
- Strict in-memory multipart mode prevents ordinary Starlette disk rollover within the accepted
  bound; it does not prevent the operating system from paging process memory.
- Detection remains heuristic. The synthetic corpus is regression evidence, not a real-world
  accuracy rate or proof that no privacy/security defect remains.

All ordered milestones were implemented in the local supported scope. The unavailable or
non-independent release evidence above remains explicitly open, so this document does not make a
general production-ready or vulnerability-free claim.
