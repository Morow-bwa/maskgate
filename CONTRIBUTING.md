# Contributing

Thanks for helping improve MaskGate.

1. Create a focused branch.
2. Add or update tests for behavior changes.
3. Run `python -m pytest` before opening a pull request.
4. Do not include real personal data, credentials, or production prompts in tests, fixtures, logs, or examples.
5. Keep provider credentials in a local `.env`; use reserved example domains and synthetic tokens in tests.
6. Run `pnpm audit --prod` in `playground-react` when changing frontend dependencies.

The project is intentionally conservative: raw request/response content and mappings must not be logged or persisted.
