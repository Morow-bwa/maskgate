from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

RULES = {
    "private-key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "openai-key": re.compile(rb"sk-(?!test-|example)[A-Za-z0-9_-]{20,}"),
    "github-token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    "google-api-key": re.compile(rb"AIza[0-9A-Za-z_-]{30,}"),
    "gemini-style-key": re.compile(rb"AQ\.[0-9A-Za-z_-]{30,}"),
    "aws-access-key": re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
}

EMAIL_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9._%+-]*)@"
    rb"([A-Za-z0-9.-]+\.[A-Za-z]{2,})"
    rb"(?![A-Za-z0-9.-])"
)
RESERVED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "example.invalid")

SKIP_SUFFIXES = {
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".webp",
}


def repository_files() -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    )
    return [Path(item.decode("utf-8")) for item in output.split(b"\0") if item]


def scan_bytes(label: str, content: bytes) -> list[str]:
    findings: list[str] = []
    for rule_name, pattern in RULES.items():
        for match in pattern.finditer(content):
            line = content.count(b"\n", 0, match.start()) + 1
            findings.append(f"{label}:{line}: {rule_name}")
    for match in EMAIL_PATTERN.finditer(content):
        domain = match.group(2).decode("ascii", "ignore").casefold()
        is_reserved = any(
            domain == reserved or domain.endswith(f".{reserved}")
            for reserved in RESERVED_EMAIL_DOMAINS
        ) or domain.endswith((".test", ".invalid"))
        if not is_reserved:
            line = content.count(b"\n", 0, match.start()) + 1
            findings.append(f"{label}:{line}: non-reserved-email")
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan repository text without printing secrets")
    parser.add_argument("--history", action="store_true", help="also scan reachable git patches")
    args = parser.parse_args()

    findings: list[str] = []
    for path in repository_files():
        if path.suffix.casefold() in SKIP_SUFFIXES or not path.is_file():
            continue
        findings.extend(scan_bytes(path.as_posix(), path.read_bytes()))

    if args.history:
        history = subprocess.check_output(["git", "log", "-p", "--all", "--format="])
        findings.extend(scan_bytes("git-history", history))

    if findings:
        print("Potential credentials found (values intentionally omitted):")
        print("\n".join(findings))
        raise SystemExit(1)
    scope = "repository files and git history" if args.history else "repository files"
    print(f"Credential pattern scan passed: {scope}")


if __name__ == "__main__":
    main()
