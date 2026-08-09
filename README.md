# MaskGate

[![CI](https://github.com/Morow-bwa/maskgate/actions/workflows/ci.yml/badge.svg)](https://github.com/Morow-bwa/maskgate/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Morow-bwa/maskgate/actions/workflows/codeql.yml/badge.svg)](https://github.com/Morow-bwa/maskgate/actions/workflows/codeql.yml)

Self-hosted privacy proxy for remote LLM APIs. MaskGate replaces supported sensitive values locally, sends the sanitized JSON upstream, and restores placeholders in the response without exposing the mapping to the provider.

This is an educational open-source project and technical showcase. It is not a compliance product or a claim that pattern matching can find every kind of personal data.

![MaskGate Playground](docs/screenshots/playground-preview.png)

```text
client -> auth + limits -> recursive sanitizer -> remote LLM API
                              |                       |
                              +-- RAM-only vault <----+
                                      |
                                restored response
```

## What is implemented

- OpenAI-compatible `POST /v1/chat/completions`, including streamed responses.
- Recursive sanitization of the actual outbound payload: messages, tool arguments, extension fields, and object keys.
- Fail-closed handling for unsafe protocol identifiers, unknown media in chat, detector/policy errors, and malformed files.
- Request-scoped random placeholders and local response restoration.
- Multi-turn conversations with bounded, tenant-isolated, RAM-only state.
- Explicit allowlists for public email addresses, domains, and public person names.
- Local anonymization endpoint for DOCX, PDF, PNG, JPEG, WEBP, TIFF, and BMP.
- Minimal Playground showing the input, exact outbound request, provider response, and restored result.
- Bearer authentication, body limits, rate limiting, trusted hosts, security headers, and production fail-closed settings.

MaskGate targets remote provider APIs. Local models are intentionally out of scope because their prompts already remain inside the operator's own environment.

## Quick start

### Windows

Requires Python 3.12 and Node.js 22 with Corepack or pnpm:

```powershell
& .\run-playground.ps1
```

Open [http://127.0.0.1:8080/playground](http://127.0.0.1:8080/playground). The first run creates `.venv`, installs the media stack, and builds the React UI. Later runs can use `-SkipInstall`.

### Docker

```bash
docker compose up --build
```

The local Compose profile binds only to `127.0.0.1` and starts in preview-only mode when no provider credentials are configured.

## Connect a remote provider

Create an untracked `.env` file. Use any remote service that exposes the configured API adapter; the browser never receives this credential.

```env
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.example.com/v1
LLM_API_KEY=replace-with-provider-key
LLM_DEFAULT_MODEL=provider-model
```

Without a provider key, the Playground still displays the exact sanitized payload but no external request is made. The API endpoint returns `provider_not_configured` instead of forwarding an unauthenticated request.

Example client request:

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"provider-model","messages":[{"role":"user","content":"Email billing@example.org"}]}'
```

## File anonymization

Files are processed locally and are never automatically sent to an LLM provider.

```bash
curl -F "file=@document.pdf" \
  -o document.masked.pdf \
  http://127.0.0.1:8080/v1/privacy/files/anonymize
```

- DOCX text, split runs, attributes, metadata, comments, and external links are sanitized; active content and embedded media are blocked.
- PDFs are rasterized page-by-page and rebuilt, removing the original text layer, links, scripts, attachments, and metadata.
- Images use local OCR and frontal-face detection, burn redactions into pixels, and are exported as metadata-free PNG.

OCR and face detection can miss content. Review sanitized files before high-risk use. Rasterized PDFs lose searchable text and accessibility structure.

## Production

Production mode requires inbound auth, explicit trusted hosts, and a configured provider. The Playground and debug endpoints are disabled.

```bash
cp production.env.example production.env
# edit every required value
docker compose --env-file production.env -f compose.production.yml up -d --build
```

Terminate TLS at a reverse proxy. Keep one application worker: conversation mappings live in process RAM. See [Deployment](docs/DEPLOYMENT.md), [Threat model](docs/THREAT_MODEL.md), and [Privacy guarantees](docs/PRIVACY_GUARANTEES.md).

## Verification

```powershell
.\.venv\Scripts\python.exe -m ruff check app scripts
.\.venv\Scripts\python.exe -m pytest --cov=app --cov-report=term-missing
.\.venv\Scripts\python.exe -m pip_audit --local
.\.venv\Scripts\python.exe scripts\check_secrets.py --history
pnpm --dir playground-react build
pnpm --dir playground-react audit --audit-level high
```

The tests include an `httpx.MockTransport` assertion against the serialized outbound HTTP body, not only an intermediate masked object. CI also builds the container, runs a real Chromium smoke test, audits dependencies, scans credential patterns, and runs CodeQL.

Current local verification: 69 tests passed, 81.8% branch coverage, React Doctor 100/100, and no known Python or npm dependency vulnerabilities.

## Repository map

```text
app/                    FastAPI proxy, masking, media pipeline, tests
playground-react/       React/Vite inspection UI
scripts/                bootstrap, browser smoke, secret scan
docs/                   threat model, deployment, privacy decisions
Dockerfile              non-root production image
compose.production.yml  hardened single-instance deployment
```

Apache-2.0. See [LICENSE](LICENSE).
