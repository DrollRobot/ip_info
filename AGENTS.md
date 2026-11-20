# Agent Rules

## Package Purpose
`ip_info` is a command-line tool that looks up IP addresses across many
third-party providers (AbuseIPDB, VirusTotal, IPinfo, IP-API, and others),
normalizes their responses into a shared shape, and presents an aggregated
report. Results are cached in a local SQLite database so repeated lookups
avoid redundant API calls. Provider API keys are optional secrets in the
config system, stored in the OS keyring, never in source or the repo.

## General rules
- Environment values are are stored in the config system. Package config schema
  is defined in src/name/config/schema.py.
- Secrets are stored only in keyvault or keyring. Never in source, never in
  plain-text on disk.
- Support only the Python versions python.org still supports
  (https://devguide.python.org/versions/), at their latest patch release.
  Old patch releases are not supported. Write every Python version with a
  patch number, except where a tool accepts only MAJOR.MINOR (mypy, ruff,
  pre-commit).
- Fail early, fail loudly. Avoid default values that could mask errors.

## Code Formatting and Style
- Follow pep8 style guidelines.
- Always include thorough docstrings for all functions and classes.
- Line length limit: 100 characters.
- Use type hints for all function signatures.

## pre-commit
- Do not fight automatic formatting. Always commit autoformatting changes, even if
  they're out of scope for the current task.
- Formatting changes and detect-secrets updates to the .secrets.baseline are routine
  and expected. If all that's required is re-staging and re-committing, DO NOT REPORT
  TO THE USER. Only report when user interaction is required.

## detect-secrets
This repo uses detect-secrets.
- Do not try to work around secret detection by renaming, splitting
  strings, `# pragma: allowlist secret`, or any other means. Let detect-secrets do
  its job. A new entry in the baseline for a user to audit is not a problem to be
  avoided. Simply tell the user an audit is required.
- Baseline updates during pre-commit checks are expected. Do not attempt to revert.
- Agents can/should freely scan for secrets:
```bash
uv run detect-secrets scan --baseline .secrets.baseline
```
- Agents should NEVER regenerate the baseline from scratch.
```bash
detect-secrets scan > .secrets.baseline
```
- Agents should NEVER attempt to audit (users only), or modify the `.secrets.baseline`
  file directly.

## Commit Messages
Review before writing commit messages: [AGENTS.COMMITTING.md](AGENTS.COMMITTING.md).

## Testing
For instructions on writing and running tests: [AGENTS.TESTING.md](AGENTS.TESTING.md).
ALWAYS READ BEFORE WRITING NEW CODE.

## Build and Release
For build and release procedures, see [AGENTS.RELEASING.md](AGENTS.RELEASING.md).
