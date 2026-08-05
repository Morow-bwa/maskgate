# MaskGate

> Educational, self-hosted demo of a privacy masking proxy for LLM requests.

MaskGate shows one concrete flow:

```text
local client → MaskGate → masked provider request
                         ← restored response
```

It is an exploratory project and a working technical showcase, not a hosted
service, commercial product, compliance certification, or production promise.

![MaskGate Playground](docs/screenshots/playground-preview.png)

## What the demo shows

The local Playground has two modules:

- **Input** — the text entered by the user.
- **Output** — the exact masked payload, provider response, and locally restored result.

When no provider key is configured, Playground runs in **preview-only mode**:
it masks the request locally and never calls OpenAI, Gemini, or another
upstream. This makes the masking flow testable without a provider account.

## Run locally

Requirements: Python 3.11+, Node.js 22+, and pnpm.

```powershell
Copy-Item .env.example .env

cd playground-react
pnpm install
pnpm build
cd ..

python -m pip install -e ".[dev]"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open [http://localhost:8080/playground](http://localhost:8080/playground).

On Windows, `./run-playground.ps1` can build the frontend when needed and
start the local server.

```powershell
& .\run-playground.ps1
```

Check the service:

```powershell
Invoke-WebRequest http://localhost:8080/health
```

## Optional provider call

The demo does not need a provider key. To test a real upstream call, put a
replacement key only in the local, untracked `.env` file:

```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=your-replacement-key
GEMINI_MODEL=gemini-2.5-flash
```

OpenAI-compatible providers use `LLM_PROVIDER=openai` and `LLM_API_KEY`.
Restart the server after changing `.env`. Provider credentials are never part
of the browser bundle or Playground request.

## Privacy behavior

1. Validate the incoming OpenAI-compatible request.
2. Detect supported sensitive values in text content.
3. Apply the YAML policy.
4. Replace allowed values with placeholders, surrogates, or redactions.
5. Send only the masked payload upstream when a provider is configured.
6. Restore request-scoped values in the provider response locally.
7. Keep conversation mappings in RAM only, with a bounded TTL and size.

API keys are blocked by default. Unsanitized images, screenshots, and other
media are rejected before an upstream call because this demo has no OCR or
visual redaction pipeline yet.

Supported patterns include email, phone, IPv4, URL, domain, API-key formats,
file paths, money, card numbers, INN, and conservative Cyrillic person names.
Regex detection is not a complete privacy guarantee; review the patterns and
policy for any real deployment.

## Security defaults

- `.env` is ignored by Git and Docker builds.
- The example configuration leaves provider keys empty.
- Debug endpoints are disabled in `.env.example`.
- `/playground` previews locally when the provider is not configured.
- `/v1/chat/completions` returns `provider_not_configured` instead of making an unauthenticated upstream request.
- Client `Authorization` headers are not forwarded to the provider.
- Raw prompts, mappings, provider keys, and authorization headers are not logged.
- Debug endpoints, when explicitly enabled, must stay on a trusted local interface.

This project has no authentication layer for public exposure. Keep it on
localhost or add authentication and network controls before using it outside a
trusted development environment.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the focused review and its
remaining demo-only risks.

## Repository map

```text
app/                    FastAPI proxy, masking, policy, storage, tests
playground-react/       React/Vite diagnostic interface
examples/               OpenAI-compatible Python and Node examples
run-playground.ps1      Windows local runner
```

## Tests

```powershell
python -m pytest -q
```

The suite covers masking, overlap resolution, policy blocks, rehydration,
streaming, conversations, media fail-closed behavior, preview-only mode, and
configuration parsing.

## License

Apache-2.0. See [LICENSE](LICENSE).
