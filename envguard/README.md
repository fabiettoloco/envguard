# envguard

Find missing environment variables, stale `.env.example` entries, and accidentally exposed secrets before they reach CI or production.

`envguard` is a small, dependency-light CLI designed for local development, CI, and pre-commit workflows.

## What it checks

- Variables referenced in source files but missing from `.env.example`
- Variables documented in `.env.example` but not referenced by the project
- High-confidence secret patterns in tracked files
- Optional JSON and SARIF reports for CI integrations
- Explicit allowlists for intentional values

## Quick start

```bash
pipx install envguard
envguard scan .
```

Example:

```text
$ envguard scan .

Environment
  missing     DATABASE_URL
  missing     STRIPE_SECRET_KEY

Secrets
  warning     config/example.py:12  AWS_SECRET_ACCESS_KEY

Summary
  2 missing variables
  1 possible secret
```

The scanner is intentionally conservative. It reports findings; it does not modify files or contact external services.

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

## Design goals

envguard is intentionally:

- local-first
- deterministic
- dependency-light
- safe to run in CI
- explicit about false positives
- useful without an account or hosted service

See `CONTRIBUTING.md` for development and contribution guidelines.
