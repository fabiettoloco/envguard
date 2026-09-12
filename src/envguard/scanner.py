from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ENV_PATTERNS = [
    re.compile(r"os\.environ(?:\.get)?\([\"']([A-Z][A-Z0-9_]+)[\"']\)"),
    re.compile(r"os\.getenv\([\"']([A-Z][A-Z0-9_]+)[\"']\)"),
    re.compile(r"process\.env\.([A-Z][A-Z0-9_]+)"),
    re.compile(r"env\[[\"']([A-Z][A-Z0-9_]+)[\"']\]"),
    re.compile(r"env\.([A-Z][A-Z0-9_]+)"),
]

SECRET_PATTERNS = [
    (re.compile(r"(?i)(aws_secret_access_key|private_key)\s*[:=]\s*[\"'][^\"']{12,}[\"']"), "possible secret"),
    (re.compile(r"(?i)(api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"), "possible credential"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
]

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build"}
SOURCE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"}


@dataclass(frozen=True)
class Finding:
    kind: str
    path: str
    line: int
    message: str


def _files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.stat().st_size > 1_000_000:
            continue
        yield path


def referenced_variables(root: Path) -> set[str]:
    found: set[str] = set()
    for path in _files(root):
        if path.suffix not in SOURCE_SUFFIXES:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for pattern in ENV_PATTERNS:
            found.update(pattern.findall(text))
    return found


def example_variables(root: Path) -> set[str]:
    paths = [root / ".env.example", root / ".env.sample"]
    path = next((p for p in paths if p.exists()), None)
    if path is None:
        return set()

    result: set[str] = set()
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return result

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", key):
            result.add(key)
    return result


def secret_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _files(root):
        # Example/config templates should not normally contain real credentials.
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(lines, 1):
            for pattern, message in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding("secret", str(path.relative_to(root)), number, message)
                    )
    return findings


def scan(root: Path) -> list[Finding]:
    refs = referenced_variables(root)
    examples = example_variables(root)
    findings = [
        Finding(
            "missing-env",
            ".env.example",
            1,
            f"{name} is referenced by source code but missing from .env.example",
        )
        for name in sorted(refs - examples)
    ]
    findings.extend(
        Finding(
            "stale-env",
            ".env.example",
            1,
            f"{name} is listed in .env.example but was not found in source code",
        )
        for name in sorted(examples - refs)
    )
    findings.extend(secret_findings(root))
    return findings
