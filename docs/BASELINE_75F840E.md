# Baseline at 75f840e

The implementation baseline was recorded before the privacy architecture changes.

## Verification

- Git revision: `75f840e4f7bcfe0bd7fd567c68c4be84ddf154ed`
- Python tests: 69 passed
- Branch coverage: 81.81%
- Ruff: clean
- Frontend build and audit: passed; no known npm vulnerabilities
- Python dependency audit: no known vulnerabilities in resolved third-party packages
- Current-file and full-history secret scans: passed

The first parallel verification attempt exposed a build/test race because the frontend build
recreated `playground-react/dist` while a Python fixture read it. Sequential verification passed;
the race was in the verification procedure, not a demonstrated privacy bypass.

## Before architecture

```text
OpenAI-shaped request
  -> one RegexDetector
  -> global entity-type policy
  -> semantic placeholder / finite surrogate / redaction
  -> OpenAI-shaped recursive sanitizer
  -> optional Gemini conversion inside the transport
  -> remote provider
  -> global replacement rehydration
```

Core privacy logic lived in `app/main.py`. The internal model was OpenAI Chat Completions. The
Gemini transformation occurred after the documented sanitizer. Four production network call sites
existed: normal and streaming calls in both `LLMClient` and `GeminiClient`.

## Verified gaps

| ID | Severity | Evidence-backed result |
|---|---|---|
| P0-01 | P0 | Finite reversible surrogate lists wrapped and caused incorrect restoration. |
| P0-02 | P0 | Base64/encoded PII in unknown fields could cross the exact HTTP body. |
| P0-03 | P0 | Numeric PII in extension fields bypassed string-only inspection. |
| P0-04 | P0 | Opaque unknown DOCX parts were copied into sanitized artifacts. |
| P1-01 | P1 | Tokens exposed entity type and sequence. |
| P1-02 | P1 | Outbound keys were transformed but response keys were not restored. |
| P1-03 | P1 | Streaming covered only `choices[0].delta.content`. |
| P1-04 | P1 | No guard inspected newly generated provider PII. |
| P1-05 | P1 | Trimmed conversation messages retained stale original mappings. |
| P1-06 | P1 | Detection had no canonicalization, validator ensemble, or measured corpus. |
| P1-07 | P1 | Policy was global `entity_type -> action`, without risk or tenant context. |
| P1-08 | P1 | Provider protocols were coupled to OpenAI Chat Completions. |
| P2-01 | P2 | Malformed SSE JSON was silently discarded. |
| P2-02 | P2 | TTL cleanup was lazy and used wall-clock time. |
| P2-03 | P2 | Media limit branches lacked direct regression tests. |

## Rejected or qualified suspicions

- No original mapping was found in normal provider requests, normal API responses, or current
  structured MaskGate request logs at the baseline.
- Distinct configured API keys were isolated in conversation storage.
- Non-streaming rehydration already traversed nested dictionary values; the defect concerned keys,
  restoration authorization, and novel provider output.
- PDF secure mode already removed original text layers, attachments, scripts, and source metadata by
  rebuilding rasterized pages.
- The React playground rendered response text without raw HTML injection.
