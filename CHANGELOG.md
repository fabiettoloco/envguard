# Changelog

All notable changes to envguard are documented here.

## 0.2.0 - 2026-09-13

### Added

- Explicit `--config` support for custom `envguard.toml` files.
- `--verbose` diagnostics on stderr.
- `--quiet` mode for CI and scripting.
- Human-readable grouped text output.
- Stable CLI exit codes: `0` for no findings, `1` for findings, `2` for usage/configuration errors.
- CLI tests covering configuration, output modes, and error handling.
- TOML configuration with ignore paths and environment-variable allowlists.
- Python 3.10 compatibility through the conditional `tomli` dependency.

### Changed

- Improved configuration and output error messages.
- JSON and SARIF output remain machine-readable while diagnostics go to stderr.

