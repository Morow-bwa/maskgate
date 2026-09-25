# Privacy engineering status board

## Current local checkpoint — 2026-09-12 through 2026-09-13

The Sol implementation pass added revocable conversation leases, setup-to-teardown ownership,
stream replay validation, global/principal admission and pre-provider retained-state reservations,
total deadlines,
reusable closed transports, path-scoped policy approvals, explicit obligation semantics, contextual
strict-memory media handling, dependency checks and fixed-label operational snapshots. The full
local gate and exact receipt are recorded in
`docs/implementation/2026-09-12/REVIEW_AND_EVIDENCE.md`.

This remains a single-process educational privacy proxy. Live providers, Linux Docker behavior and
remote CI were not verified by this local pass, and no independent second-agent audit was run.

## Previous local checkpoint — 2026-09-06

Baseline `102dcc2`: follow-up review reproduced encoded-key/size bypasses despite the earlier green
suite. Local fixes and the project harness now pass 404 tests, 83.69% coverage, the 598-case strict
corpus, frontend build and Chromium smoke. Encoded strings and keys fail closed on size/decode
budget exhaustion; long protocol IDs have round-trip regressions; SSE byte limits apply before
line buffering. See [security review](SECURITY_REVIEW_2026-09-06.md) and [harness](agent/README.md).

These are local results. Docker/live-provider checks and new remote CI were not run. The historical
independent-review statements below are not approvals of the current patch or general claims that
no vulnerabilities remain.

## Historical Phase 1 checkpoint

| Issue | Severity | State | Evidence | Review |
|---|---:|---|---|---|
| Reversible surrogate collisions | P0 | fixed | uniqueness and vault bijection tests | independent red team passed |
| Encoded outbound bypass | P0 | fixed | base64/hex/escape/nested JSON tests | independent red team passed |
| Numeric outbound bypass | P0 | fixed | strict provider numeric registries | independent red team passed |
| Opaque DOCX parts | P0 | fixed | OPC allowlist and unknown-part tests | independent red team passed |
| Post-Adapter wire enforcement | P0 | fixed for runtime providers | exact OpenAI/Gemini body tests | independent red team passed |
| Opaque token injection/collision | P1 | fixed | random grammar, injection, budget tests | independent red team passed |
| Structural key symmetry | P1 | fixed | key restoration/collision tests | independent red team passed |
| Output privacy | P1 | fixed for documented fields | new PII/token/metadata tests | independent red team passed |
| Streaming parity | P1 | fixed for Chat fields | every split/tool/multi-choice tests | independent red team passed |
| Conversation mapping GC | P1 | fixed | trim/irreversible/TTL/delete tests | independent red team passed |
| Structured assistant history | P1 | fixed | tool-call history test | independent red team passed |
| Detection v2 | P1 | integrated | recognizer/validator/canonicalization corpus | leader reviewed; quality limits remain |
| Policy/Risk v2 | P1 | integrated | strict schema/context/public assertion tests | leader reviewed |
| Principal/tenant isolation | P1 | integrated | cross-key conversation/vault tests | independent red team passed |
| Canonical IR/provider Adapters | P1 | integrated for OpenAI/Gemini runtime | round trips and exact body tests | leader reviewed |
| Media/resource limits | P2 | integrated | adversarial media/file tests | independent red team passed for DOCX |
| Privacy-safe metrics | P2 | integrated | label/cardinality/latency tests | leader reviewed |
| Application decomposition | P1 | completed | composition root plus route/orchestration Modules | leader reviewed |
| Protocol-key encoded false positives | P1 | fixed | OpenAI/Gemini schema-key regressions | independent red team retest passed |
| OpenAI stream envelope corruption | P1 | fixed | fixed-literal output regression | independent red team retest passed |
| Independent final red team | P0 gate | passed | 28-test adversarial matrix | 28 passed after fixes |

No confirmed P0 remains in the tested scope. A library Adapter is not marked runtime supported
until transport, response, streaming, output, and exact-body coverage all exist.

## Phase 2 working board

Baseline: `60d0864`; 274 tests passed; 83% branch coverage; strict corpus 28 cases.

| Work item | Priority | Baseline finding | Owner | Gate |
|---|---:|---|---|---|
| Unified detector contract and capability manifest | P0 | no common terminal capability contract | Agent A | complete: startup + automatic manifest tests |
| Final Wire Guard detector consistency | P0 | directly depended on legacy `RegexDetector` | Agent A + lead | complete: malicious Adapter values blocked post-serialization |
| Output Guard detector consistency | P0 | directly depended on legacy `RegexDetector` | Agent A + lead | complete: shared detector plus encoded-view policy |
| Detection quality and multilingual corpus | P1 | 28 cases; PHONE precision 0.50; PERSON had one positive | Agent B | complete: 598 cases and sliced metrics |
| Modern provider runtime completion | P1 | runtime status requires code and exact-wire verification | Agent C + lead | complete: stateless non-stream OpenAI Responses |
| Provider exception reflection | P1 | custom upstream message reached client | Agent D + lead | fixed: bounded local public error registry |
| Conversation hard retention bound | P2 | one oversized message survived trim | Agent D + lead | fixed: canonical size and whole-message eviction |
| Independent adversarial QA | P0 gate | pending after implementation freeze | Agent D | passed: 40 cases; 176-case combined matrix |
| Semantic quasi-identifier analysis/generalization | P2 | numeric risk scorer is not semantic anonymity | lead | advisory local findings + policy-authorized candidates complete |
| Orchestrator decomposition | P2 | intentionally deferred | lead | deferred; no privacy benefit justified churn |

No confirmed P0/P1 remains in the tested Phase 2 scope. Semantic analysis is an advisory API and
is not described as anonymity, NER, or an automatic runtime policy decision.
