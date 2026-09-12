# envguard

Find missing environment variables, stale `.env.example` entries, and accidentally exposed secrets before they reach CI or production.

`envguard` is a small, dependency-light CLI designed for local development, CI, and pre-commit workflows.

## What it checks

- Variables referenced in source files but missing from `.env.example`
- Variables documented in `.env.example` but not referenced by the project
- High-confidence secret patterns in tracked files
- Optional JSON and SARIF reports for CI integrations
- Explicit allowlists for intentional environment variables

## Quick start

```bash
pipx install envguard
envguard scan .
```

Example:

```text
$ envguard scan .

Environment variables
  .env.example:1  DATABASE_URL is referenced by source code but missing from .env.example

Possible secrets
  config/example.py:12  possible credential

Summary: 2 finding(s).
```

## CLI

```text
envguard scan [PATH] [--format text|json|sarif] [--output FILE]
               [--config FILE] [--quiet | --verbose]
```

- `--config FILE` uses a specific TOML configuration file. Without it, `envguard.toml` in the project root is discovered automatically when present.
- `--verbose` writes scan diagnostics to stderr, keeping stdout available for reports.
- `--quiet` suppresses the report while preserving the exit status.
- Exit code `0` means no findings, `1` means findings were detected, and `2` means the scan could not be completed because of invalid input or configuration.

## Configuration

Copy `envguard.toml.example` to `envguard.toml`:

```toml
[scan]
ignore = ["docs/", "fixtures/"]
allowlist = ["CI", "PATH"]
```

`ignore` excludes paths relative to the project root. `allowlist` excludes named environment variables from missing/stale environment findings.

## CI

```yaml
name: envguard

on:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install envguard
      - run: envguard scan . --format sarif --output envguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: envguard.sarif
```

## Why envguard?

envguard focuses on a common gap between application code and deployment configuration: environment variables can be referenced in source, documented in examples, or accidentally committed as secrets, and these states can drift apart. The project is deliberately local-first and deterministic so it can run in CI without an account, hosted service, or telemetry.

## Roadmap

- More language-aware environment-variable detection
- More configurable secret rules with explicit false-positive handling
- Pre-commit and reusable GitHub Actions integrations
- Better SARIF rule metadata and developer-facing diagnostics

The scanner is intentionally conservative. It reports findings; it does not modify files or contact external services.

See `CONTRIBUTING.md` for development and contribution guidelines.
