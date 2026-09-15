"""Local project context and repeatable checks; no provider calls or installation."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "agent" / "project.json"
QUICK_TESTS = [
    "test_terminal_encoding_regressions.py",
    "test_detection_boundary_consistency.py",
    "test_pipeline_wire_integration.py",
    "test_openai_responses_runtime.py",
    "test_streaming_privacy.py",
    "test_streaming_history_finalization.py",
    "test_llm_client.py",
    "test_gemini_client.py",
    "test_principal_context.py",
    "test_vault_token_security.py",
    "test_conversation_vault_lifecycle.py",
    "test_policy_v2.py",
    "test_resource_admission.py",
    "test_media_security.py",
    "test_module_boundaries.py",
    "test_wire_boundary_adversarial.py",
]


def context() -> bool:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    valid = True
    print(manifest["purpose"])
    for module in manifest["modules"]:
        print(f"\n{module['name']}: {module['responsibility']}")
        for path in module["paths"] + module["tests"]:
            exists = (ROOT / path).exists()
            valid &= exists
            print(f"  {'OK' if exists else 'MISSING'} {path}")
    print("\nRuntime support:")
    for provider, status in manifest["providers"].items():
        print(f"  {provider}: {status}")
    return valid


def doctor() -> bool:
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")
    valid = sys.version_info >= (3, 11)
    for package in ("fastapi", "httpx", "pytest", "pytest-cov", "ruff"):
        try:
            print(f"{package}: {importlib.metadata.version(package)}")
        except importlib.metadata.PackageNotFoundError:
            print(f"{package}: MISSING; run the bootstrap script")
            valid = False
    for binary in ("git", "node", "pnpm", "docker"):
        location = shutil.which(binary)
        print(f"{binary}: {location or 'unavailable'}")
        if binary == "git" and not location:
            valid = False
    print("No .env contents, credentials, or request data are read by doctor.")
    return valid


def check(*, quick: bool, frontend: bool) -> bool:
    run_dir = ROOT / "output" / "harness" / uuid.uuid4().hex
    run_dir.mkdir(parents=True)
    report: list[dict[str, object]] = []
    valid = context() and doctor()
    report.append({"name": "preflight", "exit_code": 0 if valid else 1})
    commands: list[tuple[str, list[str], Path]] = [
        ("lint", [sys.executable, "-m", "ruff", "check", "app", "evaluation", "scripts"], ROOT),
    ]
    tests = [str(Path("app/tests") / name) for name in QUICK_TESTS] if quick else ["app/tests"]
    test_command = [sys.executable, "-m", "pytest", *tests, f"--basetemp={run_dir / 'pytest'}"]
    if not quick:
        test_command += [
            "--cov=app",
            "--cov-branch",
            "--cov-report=term-missing",
            "--cov-fail-under=81.8",
        ]
    commands.append(("tests", test_command, ROOT))
    if not quick:
        commands.append(
            (
                "detection-corpus",
                [
                    sys.executable,
                    "-m",
                    "evaluation.evaluate_detection",
                    "--profile",
                    "strict",
                    "--summary",
                    "--fail-on-errors",
                ],
                ROOT,
            )
        )
    commands.append(("secret-patterns", [sys.executable, "scripts/check_secrets.py"], ROOT))
    if frontend:
        # Use the installed Vite entrypoint. A verification run must not implicitly
        # install or replace node_modules through package-manager run hooks.
        commands.append(
            (
                "frontend-build",
                [shutil.which("node") or "node", "node_modules/vite/bin/vite.js", "build"],
                ROOT / "playground-react",
            )
        )
    try:
        for name, command, cwd in commands:
            print(f"\n== {name} ==", flush=True)
            start = time.monotonic()
            try:
                result = subprocess.run(command, cwd=cwd, check=False, timeout=600)
                code = result.returncode
            except (OSError, subprocess.TimeoutExpired) as exc:
                print(f"Could not complete {name}: {type(exc).__name__}")
                code = 1
            report.append(
                {"name": name, "exit_code": code, "seconds": round(time.monotonic() - start, 2)}
            )
            valid &= code == 0
    finally:
        path = run_dir / "report.json"
        path.write_text(
            json.dumps({"mode": "quick" if quick else "full", "checks": report}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"\nCheck receipt: {path}")
    print("PASS" if valid else "FAIL: inspect the failed stages above")
    return valid


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("context", "doctor", "check"))
    parser.add_argument("--quick", action="store_true", help="Focused security regression gate")
    parser.add_argument("--frontend", action="store_true", help="Also build the installed frontend")
    args = parser.parse_args()
    if args.command == "context":
        return 0 if context() else 1
    if args.command == "doctor":
        return 0 if doctor() else 1
    return 0 if check(quick=args.quick, frontend=args.frontend) else 1


if __name__ == "__main__":
    raise SystemExit(main())
