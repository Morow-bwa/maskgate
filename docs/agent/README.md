# Project harness

Start with the trust boundary: client and provider content are untrusted; local configuration and
the running process are trusted. The goal is to keep detected, unapproved sensitive data out of
remote request bodies and restore only authorized mappings to the owning client. Detection is
heuristic. Host compromise, deliberate covert channels in protocol IDs and arbitrary encodings
are outside the guarantee.

## Commands

From the repository root with a prepared Python environment:

```sh
python scripts/harness.py context
python scripts/harness.py doctor
python scripts/harness.py check --quick
python scripts/harness.py check --frontend
python scripts/measure_resources.py
```

Windows equivalent (also supports the Codex bundled Python fallback for this machine):

```powershell
.\scripts\check.ps1 -Command context
.\scripts\check.ps1 -Command doctor
.\scripts\check.ps1 -Quick
.\scripts\check.ps1 -Frontend
```

`-Python <path>` selects a prepared interpreter explicitly. The fallback reuses existing venv
packages; it does not repair the underlying venv. For a normal installation, install Python 3.12
and use `scripts/bootstrap.ps1` or `scripts/bootstrap.sh`.

The quick gate runs lint, the module-map check, focused boundary/transport/vault regressions and
the credential-pattern scan. The full gate runs all backend tests with branch coverage (minimum
81.8%), the strict detection corpus, lint and credential patterns. `--frontend` builds the installed
React application. Missing tools, missing manifest paths, test failures and timeouts return a
nonzero exit code. Each run writes only stage names, durations and exit codes to a unique ignored
`output/harness/<run-id>/report.json`; it never writes request data. Tests use unique local temp
directories, so concurrent runs do not delete each other's artifacts.

`measure_resources.py` runs a bounded credential-free mock workload and samples this process's
Windows working set. It makes no provider calls. Record its request count, concurrency, payload
size and machine together with the result; one sample is not a universal throughput or OOM claim.

## Additional release checks

These require network access, browser binaries or Docker and are deliberately separate:

```sh
python -m pip_audit --local
pnpm --dir playground-react audit --audit-level high
python scripts/check_secrets.py --history
python scripts/browser_smoke.py --url http://127.0.0.1:8080/playground
docker build -t maskgate:check .
```

Use an isolated project environment for dependency auditing. CI additionally verifies the
production lock, benchmarks, browser flow, Docker build and CodeQL. Do not treat unavailable
checks as passes. Do not send private fixture data to real providers to test the boundary.

## Where to make changes

`project.json` connects module responsibilities to source paths and regression tests. It is a
navigation index, not generated knowledge about behavior. `ARCHITECTURE.md` defines boundaries,
`PROVIDERS.md` defines supported APIs, and tests provide executable evidence. Update these together.
Avoid rewriting `app/chat/orchestrator.py` merely to reduce its size: it coordinates several
privacy-sensitive error/history/streaming paths. Extract one responsibility at a time with route
and exact-transport tests.

## Terminal encoding limits

Both guards share `app/privacy/encoded.py`: a 64 KiB UTF-8 budget per string (including keys),
at most four decoded layers, percent and literal Unicode escapes, nested JSON and inspectable
short Base64. Long opaque Base64/Base64URL/hex fields are unsupported. Exceeding the budget blocks
the outbound request or redacts the provider field; long plain-text fields have the same budget.
Clients should split larger content into smaller supported text fields. A split is not a way to
bypass inspection: strict streaming checks completed fields.

Known schema keywords and IDs at exact protocol locations only bypass the opaque-text heuristic;
direct sensitive-data and forged-token checks still run. A protocol-shaped string in a prompt,
schema property name or nested tool data receives ordinary content inspection.
