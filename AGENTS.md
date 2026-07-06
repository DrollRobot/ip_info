# Agent Rules

## Package Purpose

`ip_info` is a command-line tool that looks up IP addresses across many
third-party providers (AbuseIPDB, VirusTotal, IPinfo, IP-API, and others),
normalizes their responses into a shared shape, and presents an aggregated
report. Results are cached in a local SQLite database so repeated lookups
avoid redundant API calls. Provider API keys are stored via `keyring` (the OS
credential store), never in source or the repo.

## General rules

- All environment specific values should live in .env, not in source.
- Fail early, fail loudly. Avoid default values that could mask errors.

## Code Formatting and Style

- Follow pep8 style guidelines.
- Always include thorough docstrings for all functions and classes.
- Line length limit: 100 characters.
- Use type hints for all function signatures.

## Writing Tests for New Code

- All new code should have tests for every branch.
- Pure logic branches (parsers, utilities with no network or I/O) get unit
  tests in `tests/`.
- Tests for branches with external calls (HTTP, DB) should be marked
  `@pytest.mark.integration`.

## Testing after code changes

After writing new code, run tests as described in [AGENTS.TESTING.md](AGENTS.TESTING.md).

## Build and Release

For build and release procedures, see [AGENTS.RELEASING.md](AGENTS.RELEASING.md).
