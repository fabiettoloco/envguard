# Contributing

envguard is intentionally small. Contributions should keep the scanner predictable and avoid adding network calls or telemetry.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

For changes that affect detection rules, add a focused test and explain the false-positive tradeoff in the pull request.

## Pull requests

Please keep pull requests focused and include tests for behavior changes. Security-related changes should explain what is detected, what is deliberately not detected, and any expected false positives.
