# Security review

Date: 2026-08-09
Scope: FastAPI proxy, provider adapters, React Playground, media pipeline, deployment files, dependencies, tests, and repository hygiene.

This is an internal engineering review of an educational project, not a penetration test or certification.

## Resolved high-risk findings

### Outbound data escaped message-only masking

Tool arguments, provider extension fields, and object keys could have bypassed a `messages[].content`-only implementation. MaskGate now recursively sanitizes every outbound string and key at the final provider boundary. Protocol identifiers are inspected and grammar-validated; unsafe values block before HTTP.

Evidence: tests assert against the serialized body received by `httpx.MockTransport`, including nested metadata and object keys.

### Missing provider key reached the remote API

Example-like or empty provider credentials now make the service not ready. Playground uses local preview-only mode; the compatible API returns `provider_not_configured`. No unauthenticated upstream request is attempted.

### Public deployment lacked abuse controls

Production now requires Bearer authentication and explicit trusted hosts, disables Playground/debug routes, and applies constant-time key comparison, canonical-identity rate limiting, request/file limits, security headers, bounded state, and non-forwarding of client authorization.

### Conversation state could cross tenant or exhaust memory

Conversation state is keyed by a hash-derived security identity and conversation ID. TTL, message, character, and conversation-count bounds are enforced; capacity exhaustion returns 503 before provider access.

### File support had no privacy-safe boundary

The file endpoint is local-only and fail closed. DOCX archives are checked for traversal, duplicates, expansion size/ratio, active content, and unverifiable embedded objects. PDFs are rebuilt from sanitized pixels. Images burn OCR/face redactions into a metadata-free PNG and are verified again before return.

### Deployment and dependency drift

The production dependency graph is pinned in `requirements.lock`; pnpm has an integrity lock. CI runs lint, tests/coverage, dependency audits, credential-pattern scanning, Chromium smoke, Docker build, and CodeQL. Dependabot covers Python, npm, Docker, and Actions.

The container runs as UID 10001. Production Compose adds a read-only root filesystem, no capabilities, `no-new-privileges`, health checks, and process/resource limits.

## Residual risks

- Detector quality is not perfect: regex, OCR, and frontal-face detection can miss sensitive content.
- Remaining context may enable semantic re-identification even when direct identifiers are masked.
- RAM-only mappings are visible to a compromised host and disappear on restart.
- Rate limits and conversations are process-local; one worker is required.
- The app does not terminate TLS. A reverse proxy and outbound network policy are operator responsibilities.
- Rasterized PDFs lose search, links, forms, and accessibility structure.
- DOCX embedded media/objects, audio, video, spreadsheets, and legacy document formats are blocked or unsupported.
- Docker could not be built in the original Windows development environment because Docker was not installed; CI is the authoritative container build check.

## Verification commands

```powershell
.\.venv\Scripts\python.exe -m ruff check app scripts
.\.venv\Scripts\python.exe -m pytest --cov=app --cov-report=term-missing
.\.venv\Scripts\python.exe -m pip_audit --local
.\.venv\Scripts\python.exe scripts\check_secrets.py --history
pnpm --dir playground-react build
pnpm --dir playground-react audit --audit-level high
```

Local result on 2026-08-09: 69 tests passed, 81.8% branch coverage, React Doctor 100/100, no known Python/npm dependency vulnerabilities, and no credential-pattern or non-reserved-email findings in repository files or reachable Git history.

See [Threat model](docs/THREAT_MODEL.md) and [Privacy guarantees](docs/PRIVACY_GUARANTEES.md) for the exact boundary and non-guarantees.
