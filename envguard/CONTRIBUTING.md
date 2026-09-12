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
