# Deployment

## Supported topology

Run one MaskGate process behind a TLS-terminating reverse proxy. Do not expose Uvicorn directly to the public internet.

```text
client -> TLS reverse proxy -> MaskGate (1 worker) -> remote provider API
```

Conversation and response-restoration mappings are process-local RAM state. Multiple workers or replicas require a privacy-reviewed shared vault plus sticky conversation routing; neither is implemented here.

## Production Compose

```bash
cp production.env.example production.env
# replace keys, host, base URL, and model
docker compose --env-file production.env -f compose.production.yml config
docker compose --env-file production.env -f compose.production.yml up -d --build
```

The image runs as UID 10001 with no Linux capabilities. Compose adds a read-only root filesystem, `no-new-privileges`, bounded PIDs/CPU/memory, and a temporary `/tmp` filesystem.

## Required controls

- Generate a long random `MASKGATE_API_KEYS` value and rotate by temporarily listing old and new values comma-separated.
- Set `TRUSTED_HOSTS` to the exact reverse-proxy Host value.
- Keep `ENABLE_PLAYGROUND=false` and `ENABLE_DEBUG_ENDPOINTS=false` in production; the application enforces this.
- Terminate TLS at the reverse proxy and restrict direct access to port 8080.
- Keep provider credentials in a secret manager or protected environment file, never in Compose YAML or the repository.
- Do not add a persistent volume for application state.
- Set upstream egress rules to the intended provider domains. Production rejects non-HTTPS provider URLs and URLs containing credentials, query strings, or fragments.

## Health endpoints

- `/health/live`: process liveness.
- `/health/ready`: configuration readiness; returns 503 when no real provider credential is configured. It does not make a provider network call.

## Capacity and limits

Rate limiting and conversation limits are in-process. The defaults are conservative demonstration values; tune body/file limits and OCR concurrency to the host. PDF rasterization and OCR are CPU- and memory-heavy, so preserve the container limits and keep `MEDIA_MAX_CONCURRENCY` low.

## Upgrade procedure

1. Review Dependabot and CodeQL results.
2. Regenerate `requirements.lock` with `python -m uv pip compile pyproject.toml --extra media --universal --output-file requirements.lock`.
3. Run all commands in the README verification section.
4. Build and scan the container in CI.
5. Deploy a new single instance and verify both health endpoints before routing traffic.
