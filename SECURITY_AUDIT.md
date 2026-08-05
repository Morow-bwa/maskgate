# Security audit

Scope: the FastAPI proxy, the React Playground, local configuration, tests, and
repository hygiene. This is a review of an educational demo, not a production
security certification.

## Summary

- No user-provided personal data or the previously shared provider key is
  present in the working tree.
- All email addresses in fixtures and examples use reserved domains such as
  `example.com`, `example.org`, `.test`, or `.invalid`.
- The only `sk-` values are deliberately synthetic `sk-test-*` fixtures used to
  test detection and masking.
- `.env`, provider credentials, key files, build output, and local dependency
  directories are excluded by Git and Docker ignore rules.

## Findings and changes

### SEC-01 — accidental unauthenticated upstream request — fixed

The proxy now determines provider readiness before an upstream call
(`app/main.py:114-117`). Playground requests use a local preview when no real
provider key is configured (`app/main.py:655-663`), while the public-compatible
`/v1/chat/completions` route returns `provider_not_configured` instead of
forwarding an empty Authorization header (`app/main.py:521-531`). This removes
the confusing upstream authentication error from the demo UI.

### SEC-02 — configuration parser fallback — fixed

Invalid integer environment values now fall back to their defaults and the
port is clamped to a positive value (`app/config.py:15-27`, `app/config.py:85`).

### SEC-03 — debug and secret exposure defaults — fixed

Debug endpoints are disabled in the example configuration
(`.env.example:30`). The repository ignores local environment files and common
credential containers (`.gitignore`, `.dockerignore`). Response headers add
`nosniff`, `no-referrer`, and `no-store` for API/debug responses
(`app/main.py:138-144`).

### SEC-04 — raw-data lifetime — reviewed

Mappings are held in RAM only, are request-scoped, and are deleted after the
request path completes; the mapping store explicitly does not write mappings
to disk or logs (`app/storage/mapping_store.py:18-20`, `app/main.py:723-725`).
Conversation memory is bounded by TTL, message count, and character count.

## Residual risks

- The demo has no authentication or rate limiting. Keep it bound to localhost;
  add an auth layer and network controls before exposing it to a network.
- Regex masking is not a complete PII detector. Review and extend the patterns
  and policy for each deployment.
- Debug endpoints intentionally return detection/mapping details when enabled;
  only enable them on a trusted local interface.
- Images, screenshots, and other media are rejected because this demo has no
  OCR or visual redaction pipeline.
- `pip-audit` was not available in the local runtime, so Python dependency
  advisories still need a separate environment check.
- `pnpm` release-age hardening is set to two days. A stricter `trustPolicy` was
  tested but rejected the current lockfile's existing transitive dependency;
  refresh the lockfile before tightening it further.

## Verification

- `python -m pytest -q` — 38 passed.
- `pnpm build` — passed.
- `pnpm audit --prod` — no known vulnerabilities.
- React Doctor — no React correctness warnings remain; only the pnpm
  hardening warning described above remains.
- Repository scan — no matches for the user's supplied names, addresses,
  identifiers, literal provider credentials, or non-reserved email domains.
  Detector regex definitions are expected to mention credential formats.
