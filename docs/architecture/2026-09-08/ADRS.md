# Architecture decision records

Date: 2026-09-08.
Status of every record: selected for this target design; not implemented and not yet promoted
to the accepted historical ADR directory. Numbering follows existing ADR-0001 through ADR-0010.

Read the [blueprint](ARCHITECTURE_BLUEPRINT.md) for evidence, migration order and limits.

## ADR-0011 — Retain a modular monolith and local RAM deployment

### Context

MaskGate's sensitive state and conversation identity are process-local. Existing modules already
separate detection, policy, IR, adapters and terminal guards. Confirmed problems concern output
history and state lifecycle; internal network services would not fix them. No durable jobs or
multi-host continuity requirement has been established.

### Decision

Keep one application process with explicit in-process module contracts and bounded RAM state.
Continue using a controlled TLS/egress deployment. Extract responsibilities incrementally; do not
replace the product with microservices. This extends, and does not supersede, ADR-0002/0010.

### Alternatives

Service-oriented gateway/privacy/vault/provider services would require distributed identity,
encryption, deletion and expiry. Hybrid asynchronous media workers would add job and artifact
retention semantics. Both remain future options tied to measured needs.

### Consequences

Lowest operational overhead and fewest network trust crossings. Restart loses sessions and one
process remains a failure domain. Reconsider when required continuity, capacity or media crash
isolation cannot be achieved under this deployment contract.

## ADR-0012 — Own conversation state through leases and generations

### Context

The current store can expire a locked state and create another for the same key. Stale commit
silently returns. A copied mapping list remains usable by an in-flight operation after the store
entry is deleted. Streaming cleanup is distributed among error branches and generator teardown.

### Decision

Make the conversation lifecycle service the authority for writer leases, revisions, mode,
generation, quotas, expiry and deletion. Use a staged private snapshot and atomic history/vault
commit. Commit returns success or a typed conflict/revocation outcome. A separate absolute deadline
bounds live operations; idle TTL never creates a second writer beside a leased generation.

Explicit deletion revokes the generation immediately. Restoration and commit require a live
permit. Cancel active work and drain references without holding the global index lock across I/O.
Teardown is idempotent and enclosed by one operation owner, including pre-stream setup.

### Alternatives

Adding more `finally` blocks without ownership leaves deletion/expiry semantics fragmented.
Keeping locks forever defeats retention and availability. Locking a global store over provider
I/O serializes unrelated users. A distributed lock is unnecessary for one process.

### Consequences

More explicit state types and lifecycle tests, but a smaller set of valid transitions. Delete
cannot recall bytes already sent or queued to the socket. Request cancellation after commit may
leave a committed turn without client acknowledgement. No exactly-once network transaction is claimed.

## ADR-0013 — One output finalizer with separate history and client projections

### Context

Non-stream Chat sanitizes history separately, while streaming stores `provider_text()` directly.
The reproduced result is redacted client output but raw new provider PII in history. Streaming
history also lacks full structured assistant state, and buffering uses array positions.

### Decision

Introduce a typed completed provider response and one output finalization use case. Its outputs
are `ProviderSafeHistory` and a client projection restored only with an active permit. Storage
accepts only the history type. Stream accumulation keys fields by semantic choice/tool identity
and produces the same completed-response semantics as non-streaming.

Continue strict buffering of sensitive fields. Validate completion and perform local commit before
the successful terminal marker. Preserve tool calls/results, refusal and supported finish state.

### Alternatives

Sanitizing only client chunks leaves retention unsafe. Storing restored client output leaks originals
into later requests. A separate permanent streaming policy would duplicate semantics. Immediate
character emission cannot preserve the current fragmented-sensitive-value guarantee.

### Consequences

Higher time to first safe text is intentional. Structured response accumulation requires budgets
and protocol tests. Format-specific decoding remains in codecs; the finalizer does not become a
provider-specific transport or a history writer.

## ADR-0014 — Preserve scoped authorization evidence through translation

### Context

Policy v2 makes contextual decisions, but approved originals are flattened into a value set for
terminal inspection. Chat and Responses use different path vocabularies. The terminal interface
cannot verify original decision scope or expiry, even though it still inspects the actual bytes.

### Decision

Represent exceptions as scoped, expiring approval evidence issued by policy and tied to the
trusted operation context and exact occurrence or explicitly reviewed semantic path. Provider
serialization supplies provenance to final wire validation. The guard verifies applicability;
it never invents a broader permission. Missing provenance or expired approval rejects the exception.

Keep request-local evidence in RAM. Do not log originals or matching hashes. Revalidate historical
public approvals at later sends. Preserve the single PrivacyDetector contract and capability gate.

### Alternatives

Global string allowlists lose context. Re-running arbitrary policy against destination paths
without provenance can change intended meaning. Giving adapters authority to declare content safe
would remove the independent terminal boundary.

### Consequences

More explicit transformation metadata, especially for tools and structured output. Some legacy
configurations need migration. Fail-closed rejection remains acceptable when an exception cannot
be represented safely; a generic policy/provenance framework is not a goal.

## ADR-0015 — Bound aggregate resources and operation lifetime

### Context

Per-string, per-vault and request byte limits exist, but their aggregate can exceed the container
memory envelope. Rate limiting does not bound active work. Idle network timeout does not bound
total stream duration, and synchronous work inside async routes is not preempted by a timer.

### Decision

Reserve global/principal/operation capacity before expensive buffering and cloning. Account for
history, mapping indexes, decoded views, streams and native media. Reject excess work explicitly.
Give every operation a monotonic absolute deadline, bounded lock waiting and deterministic teardown.
Retain current per-field decoding limits and add aggregate work budgets.

Use application-owned connection pools with explicit limits and a hard restriction on persistent
cookies, forwarded client headers and redirects. Default generation retries remain disabled.

### Alternatives

Increasing container memory alone postpones failure. Unbounded queues retain raw content and
amplify latency. Multi-worker deployment breaks the current state contract. A timeout around a
native thread does not terminate its underlying computation.

### Consequences

Some requests are rejected earlier at 429/503. Supported capacity becomes a measured deployment
property. Hard media crash/cancellation isolation may require a supervised subprocess later; the
selected design does not falsely claim that a capacity limiter provides that isolation.

## ADR-0016 — Separate compatibility policy from enforceable semantics

### Context

The process constructs a legacy policy and Policy v2. Media uses legacy decisions without the
principal/purpose context present on text routes. Obligation strings are accepted but not dispatched
as enforceable actions; examples therefore imply behavior that is not implemented.

### Decision

Use one validated decision contract for remote text and local media, with explicit context per
route. Media applies irreversible rendering and does not create an LLM upload permission. Legacy
configuration is translated through a named compatibility adapter and tested against its intended
behavior. No silent fallback when v2 denies or fails.

Classify obligations into supported enforceable controls and non-enforcing annotations. Unknown
mandatory obligations reject policy configuration. `REQUIRE_REVIEW` remains a request denial until
there is an explicitly authorized review workflow; it does not create a persistent review queue.

### Alternatives

Keep two policies indefinitely and document divergent behavior, or remove legacy behavior in one
breaking rewrite. Neither addresses the current context gap with an incremental compatibility path.

### Consequences

Policy examples and deployments need explicit migration validation. Mandatory external audit/alert
requirements may be rejected until infrastructure is separately designed. No alert is sent merely
because a policy string names an owner.

## ADR-0017 — Explicit checked transport and provider codec contracts

### Context

Built-in clients already send immutable checked bytes. Application dispatch still supports duck
typing and dictionary test doubles; transport clients contain provider conversions, and Responses
shares a Chat error helper while bypassing its Chat-specific pipeline validation.

### Decision

Keep the checked-byte invariant and make runtime transport, destination and provider capability
contracts explicit. Pure codecs own format conversion; transports own authentication, connection
lifecycle and bounded reading. Chat and Responses share inward contracts and execution primitives,
while retaining format-specific coordinators/validators. Only bootstrap selects implementations.

Retain direct-library dictionary compatibility only through an explicitly named guarded adapter
outside the runtime transport port. A new provider requires exact-wire, response, auth and stream
tests plus an updated support matrix; class presence is insufficient.

### Alternatives

One universal orchestrator would centralize unrelated schema behavior. Duplicating full pipelines
preserves drift. Removing the final guard in favor of typed IR would miss post-adapter mistakes.

### Consequences

Tests need explicit port-compatible fakes. Shared error DTOs move out of Chat. Provider support
does not expand as a side effect of extraction. Python type/seal conventions protect against
accidental trusted-code misuse, not malicious code already running in the process.

## ADR-0018 — Content-free telemetry; mandatory audit is separate

### Context

Safe logs and bounded metric enums exist, but several terminal metrics are not emitted. Local
Playground traces intentionally contain provider/request context. A future generic trace exporter
could accidentally turn those diagnostics into externally retained sensitive data.

### Decision

Keep telemetry interfaces limited to fixed event codes, bounded taxonomy, server IDs, counts and
histograms. Add missing stage emission and a protected/internal aggregate exporter. Diagnostic
client traces never implement the telemetry DTO. No automatic body/header/URL instrumentation.

Operational telemetry is best effort and non-blocking. A separately configured mandatory audit
receipt is an explicit policy obligation; reject unsupported obligations before serving requests.
Do not introduce durable audit storage without its own retention and threat model.

### Alternatives

Raw structured logs would be easy to troubleshoot but violate sensitive-data locality. A mandatory
remote telemetry dependency on every request would couple availability and privacy to a new service.

### Consequences

Less forensic payload detail by design. Operators use synthetic reproduction and safe correlation.
Current availability/SLO candidates remain unproven until deployed measurements exist.

## ADR-0019 — Make raw upload storage an explicit deployment boundary

### Context

The file route receives UploadFile. The installed parser spools files above 1 MiB to a temporary
file. Container `/tmp` is tmpfs, while the native Windows temp directory is not established as
volatile RAM. Vault RAM-only properties do not automatically apply to upload buffers.

### Decision

Strict file mode requires bounded RAM ingestion or an explicitly verified private volatile spool.
Admission must precede large buffering; cleanup must cover parse errors, cancellation and completed
downloads. If a platform cannot establish this boundary, disable strict file mode and clearly
describe any separately allowed weaker mode. Never claim ordinary temp-file deletion zeroizes data.

### Alternatives

Relying on framework defaults leaves a hidden persistence dependency. Raising an unbounded in-memory
spool threshold exchanges disk risk for OOM. A persistent encrypted document service adds an
unnecessary trust boundary for the current synchronous endpoint.

### Consequences

Large-upload tests must inspect actual spool behavior on supported deployment platforms. Native
media libraries may have additional scratch behavior to audit. Host compromise, swap and reliable
memory zeroization remain outside the guarantee.
