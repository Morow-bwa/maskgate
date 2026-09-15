# Contributing

Thanks for helping improve MaskGate.

1. Create a focused branch.
2. Add or update tests for behavior changes.
3. Run `python scripts/harness.py check --frontend` (Windows: `scripts/check.ps1 -Frontend`),
   then the network audits and release checks from `docs/agent/README.md` before opening a PR.
4. Do not include real personal data, credentials, or production prompts in tests, fixtures, logs, or examples.
5. Keep provider credentials in a local `.env`; use reserved example domains and synthetic tokens in tests.
6. Regenerate `requirements.lock` with `python -m uv pip compile pyproject.toml --extra media --universal --output-file requirements.lock` when Python dependencies change.
7. Run `pnpm audit --audit-level high` in `playground-react` when changing frontend dependencies.

The project is intentionally conservative: raw request/response content and mappings must not be logged or persisted.

See `AGENTS.md` for the change workflow and `docs/agent/project.json` for the module/test map.
