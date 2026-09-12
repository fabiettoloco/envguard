from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility
    import tomli as tomllib

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


@dataclass(frozen=True)
class ScanConfig:
    ignore: tuple[str, ...] = ()
    allowlist: frozenset[str] = frozenset()


def load_config(root: Path, config_path: Path | None = None) -> ScanConfig:
    path = config_path or (root / "envguard.toml")
    if not path.exists():
        if config_path is not None:
            raise ValueError(f"config file does not exist: {path}")
        return ScanConfig()
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"Invalid configuration: {exc}") from exc

    scan = data.get("scan", {})
    if not isinstance(scan, dict):
        raise ValueError("[scan] must be a table")

    ignore = scan.get("ignore", [])
    allowlist = scan.get("allowlist", [])
    if not isinstance(ignore, list) or not all(isinstance(item, str) for item in ignore):
        raise ValueError("[scan].ignore must be an array of strings")
    if not isinstance(allowlist, list) or not all(isinstance(item, str) for item in allowlist):
        raise ValueError("[scan].allowlist must be an array of strings")

    return ScanConfig(tuple(ignore), frozenset(allowlist))


def _files(root: Path, config: ScanConfig):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        relative = path.relative_to(root).as_posix()
        if any(relative == item.rstrip("/") or relative.startswith(item.rstrip("/") + "/") for item in config.ignore):
            continue
        if path.stat().st_size > 1_000_000:
            continue
        yield path


def referenced_variables(root: Path, config: ScanConfig | None = None) -> set[str]:
    config = config or ScanConfig()
    found: set[str] = set()
    for path in _files(root, config):
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


def secret_findings(root: Path, config: ScanConfig | None = None) -> list[Finding]:
    config = config or ScanConfig()
    findings: list[Finding] = []
    for path in _files(root, config):
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(lines, 1):
            for pattern, message in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding("secret", str(path.relative_to(root)), number, message))
    return findings


def scan(root: Path, config_path: Path | None = None) -> list[Finding]:
    config = load_config(root, config_path)
    refs = referenced_variables(root, config)
    examples = example_variables(root)
    findings = [
        Finding("missing-env", ".env.example", 1, f"{name} is referenced by source code but missing from .env.example")
        for name in sorted(refs - examples - config.allowlist)
    ]
    findings.extend(
        Finding("stale-env", ".env.example", 1, f"{name} is listed in .env.example but was not found in source code")
        for name in sorted(examples - refs - config.allowlist)
    )
    findings.extend(secret_findings(root, config))
    return findings
