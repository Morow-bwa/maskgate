# Security and maintainability review — 2026-09-06

Reviewed local baseline `102dcc2` on `codex/phase2-privacy-consistency`. The working tree was clean
before this review. Confirmed terminal privacy bypasses and an SSE resource-limit defect were
fixed locally, with rejection and compatibility regressions. A project harness now connects
architecture, source paths, tests and CI. This is a bounded code review, not a guarantee that all
vulnerabilities have been found or that live deployment is secure.

## Scope and method

Inspected FastAPI authentication/configuration, principal isolation, transport and response
handling, terminal detection/encoding, mapping/history, logging, media upload controls, React
rendering and deployment/CI configuration. Used synthetic data and mock HTTP transports; no
production requests or provider credentials were used. Existing coverage passed before fixes:
376 tests. Added regression tests first for encoding and newline-free SSE, observed failures,
then fixed the implementation and ran the entire suite and the existing browser smoke.

The client and provider are untrusted. The host, process, local configuration and in-process
extensions are trusted. Final-wire tests protect the last defense even when an earlier adapter
or transformation passes unsafe data through; they do not imply every public route accepted
every fixture before the fix.

## Confirmed security findings

### MG-001 — High: encoded keys and short Base64 bypassed terminal inspection (fixed)

- **Location:** baseline `app/privacy/wire.py`, `_inspect`, key exclusion;
  `app/privacy/output_guard.py`, `_redact_encoded`, unconditional key return.
- **Evidence:** baseline branches skipped encoded inspection for `path[-1] == "<key>"`.
  Base64 matching also missed the 23-character unpadded encoding of the synthetic email
  `owner@example.com`. The new direct-transport test reached the mock provider before the fix.
- **Impact:** encoded sensitive content could cross the final provider boundary and survive
  output/history inspection, defeating the intended last privacy defense.
- **Fix:** keys and values share `decoded_views()` in `app/privacy/encoded.py:75`; inspect
  short UTF-8 Base64 candidates, reject long opaque candidates, and use a finite schema vocabulary.
  Both final guards invoke the shared implementation (`wire.py:187`, `output_guard.py:162`).
- **Regression:** `test_terminal_encoding_regressions.py` covers both keys and values, sanitized
  history, and zero HTTP calls when rejected. Ordinary schema keywords remain usable.
- **Scope note:** arbitrary encodings and deliberate covert channels are not complete-DLP claims.

### MG-002 — High: inspection-budget exhaustion allowed content through (fixed)

- **Location:** baseline `wire.py`, `_inspect_encoded`; `output_guard.py`, `_redact_encoded`
  and `_first_unapproved_entity`.
- **Evidence:** strings over 64 KiB returned without encoded inspection; nested output decoding
  returned success at its depth limit. Mixed percent/Base64 views were not consistently revisited.
- **Impact:** padding an encoded field beyond the inspection threshold could make otherwise
  rejected sensitive data pass the final boundary.
- **Fix:** 64 KiB UTF-8 per-string bounds apply before detection, including keys. Shared decoding
  checks every supported view and rejects further decoding after four layers. Outbound data is
  blocked and provider fields are redacted on exhaustion. A single percent escape is inspected.
- **Regression:** oversized ASCII/UTF-8, short/unpadded Base64, nested escapes and mixed encodings.
- **Compatibility:** the 64 KiB bound also applies to plain-text fields. This is an intentional
  tightening; callers with larger fields must restructure input into supported smaller fields.
  Strict streaming applies the bound to completed fields, not individual network chunks.

### MG-003 — High: SSE limit was enforced after unbounded line buffering (fixed)

- **Location:** `app/proxy/llm_client.py:75`, `bounded_sse_lines` (shared by runtime transports).
- **Evidence:** baseline iterated `response.aiter_lines()` before counting bytes. A synthetic
  newline-free stream consumed all 20 chunks despite a limit reached after the third chunk.
- **Impact:** an untrusted upstream could force excess buffering by withholding a newline.
- **Fix:** count incoming bytes before incremental UTF-8 decoding and line buffering; preserve
  LF, CR, CRLF and Unicode split across network chunks. Malformed encoding and deeply invalid JSON
  produce bounded upstream errors. The regression now stops after exactly three 512-byte chunks
  for a 1,024-byte budget.
- **Operating limit:** this bounds application buffering; HTTP decompression, socket concurrency
  and host memory also need deployment limits. See [OWASP API4](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
  and [Python JSON guidance](https://docs.python.org/3.12/library/json.html).

### MG-004 — Medium: numeric arrays borrowed scalar protocol exceptions (fixed)

- **Location:** `app/privacy/wire.py`, `_is_safe_protocol_number`.
- **Evidence:** removing integer path components made `temperature[0]` equivalent to `temperature`.
- **Impact:** malformed adapter output could send numeric user data using a scalar protocol
  exception. Earlier schema validation is useful defense but cannot replace the final check.
- **Fix:** compare the complete path. A genuine scalar temperature remains allowed; a numeric
  array at that location is rejected. Nested encoded numeric user data is also redacted on output.

## Compatibility and engineering fixes

- Long `resp_*`, `msg_*`, `fc_*`, `call_*` and Chat completion/tool IDs are recognized only at
  exact protocol paths with bounded grammar (`encoded.py:37`). Direct sensitive-value/token
  detection still runs. Protocol-shaped content in prompts, keys or nested data stays inspected.
  A two-request Responses tool round trip verifies unchanged IDs and masked exact outbound bytes.
- `WirePrivacyViolation` is caught before its `PolicyBlocked` superclass in the Responses route,
  preserving the dedicated error classification (`app/responses/orchestrator.py:120`).
- Output transformation failures are converted to the pipeline's public invalid-response error
  (`app/privacy/pipeline.py:104`). Raw exception text is not returned.
- Added fragmented IBAN/JWT tests at every split point in text and tool-argument streams.
- Added `AGENTS.md`, the source/test map and workflow under `docs/agent/`, `scripts/harness.py`,
  and the Windows wrapper. CI uses the same full backend gate as local development.
- The corpus CLI now supports a real failing gate (`--fail-on-errors`) and a compact summary.
  A deliberately mismatched synthetic corpus proves that a failure returns a nonzero exit code.
- Windows bootstrap now stops at native-command failure instead of printing a false ready message.
  The check wrapper can reuse the bundled Python and existing packages when the venv launcher
  references a removed Python installation. It does not delete or silently rebuild the venv.

## Verification

| Check | Measured result |
|---|---|
| Full local harness | PASS; 404 tests, 83.69% branch-aware coverage |
| Strict detection corpus | 598 cases; 0 false positives and 0 false negatives on this corpus |
| Ruff | PASS |
| React/Vite build | PASS; installed Vite 8.2.1 matches lockfile |
| Chromium browser smoke | PASS; local masking preview and image sanitization/download |
| Repository and reachable-history credential-pattern scan | PASS; patterns are not a proof of secret absence |
| Python production lock audit | PASS; 43 dependencies applicable on Windows, no known vulnerabilities reported |
| Installed Python environment audit | PASS for 82 third-party packages; local `maskgate` package has no PyPI advisory record and was reviewed as source |
| Frontend dependency audit | PASS; no known vulnerabilities reported |
| Docker / live provider / new remote CI | Not run in this review; Docker CLI is unavailable locally |

Local evidence is under ignored `output/`: `security-final-check.log`,
`harness/9886db12c9024cf7b7b8e3b035242fd0/report.json`, `security-lock-audit.json`, and
`security-installed-audit.json`, plus `security-browser-smoke.png`. These are local check artifacts,
not committed production data.

## Remaining operating limits and next priorities

1. Run remote CI and Docker validation before release. Local tests do not verify a Linux image or
   deployment configuration. This review did not merge, push, deploy, or inspect current PR status.
2. Keep the documented provider matrix: Responses is a non-stream subset; Anthropic Messages and
   Gemini Interactions are library adapters only. Live-provider interoperability remains untested.
3. Detection and OCR/face sanitization remain heuristic. The synthetic corpus is a regression
   instrument, not a statistical measurement of privacy performance on real user documents.
4. The RAM vault remains single-process. Multi-worker/distributed state requires a separate
   design for ownership, encryption, expiry and failure behavior.
5. Protocol IDs are necessarily opaque, and arbitrary encodings or data split across independent
   fields can form covert channels. Do not present this proxy as complete DLP or compliance proof.
6. Preserve behavior while gradually extracting responsibilities from the large Chat orchestrator;
   prioritize exact transport, history and streaming tests over a wholesale rewrite.

Historical claims in earlier status documents are superseded by this review for these findings.
No new independent-agent audit was run; the evidence here is the local review and executed checks.
