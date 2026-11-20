# Tests

## Writing tests

- All new code should have unit and integration tests, and e2e/live tests
    wherever possible.
- All tests should use the tag system described below. Tests MUST have at least
    one Scope tag (`unit`, `integration`, or `e2e`).

### Test Tags

| Tag | Axis | Description |
|------|------|-------------|
| `unit` | Scope | Single function/class in isolation; all dependencies mocked or stubbed. |
| `integration` | Scope | Multiple real components wired together across a boundary. |
| `e2e` | Scope | Whole application end to end, driven like a real user. |
| `smoke` | Purpose | Fast "is it fundamentally broken" check. |
| `regression` | Purpose | Guards against reintroduction of a previously fixed bug. |
| `acceptance` | Purpose | Verifies behavior against a requirement or user-facing spec. |
| `functional` | Purpose | Tests behavior/output of a feature without regard to internal structure. |
| `live` | Dependency | Requires a real external resource - network, live tenant, secrets, third-party API. |
| `destructive_local` | Dependency | Mutates the host/device running pytest. Skipped by default. |
| `destructive_remote` | Dependency | Mutates a remote/external system. Skipped by default. |
| `slow` | Performance | Long-running. |

## Running tests

- Tests should be run before committing code.
- Use the test procedure below.
```
# if pyproject.toml was changed:
uv sync --all-extras
uv lock --check

# code checks and formatting
uv run ruff check .                 # lint
uv run ruff format .                # apply ruff formatting
uv run mypy                         # type check (targets set in pyproject.toml)
uv run vulture                      # dead code (paths set in pyproject.toml)

# if package requires cross-platform support: type check the other OS targets
# (bare `uv run mypy` above only checks the host platform)
uv run mypy --platform win32        # type check as Windows
uv run mypy --platform darwin       # type check as macOS
uv run mypy --platform linux        # type check as Linux

# tests (destructive tests are skipped by default; see note below)
uv run pytest -m "not live"         # offline tests
uv run pytest                       # live and not-live tests (when credentialed)
```

## Destructive tests
Destructive tests make permanent changes, so normal test runs skip them. There
are two kinds:

| | Local (`destructive_local`) | Remote (`destructive_remote`) |
|---|---|---|
| Changes | This computer | Another system (cloud resource, database, API tenant, ...) |
| Command | `uv run pytest --run-destructive-local` | `uv run pytest --run-destructive-remote` |
| Safety check (tests fail unless it passes) | `DISPOSABLE_ENVIRONMENT` is `1` | `tests/verify_remote_disposable.py` finds the remote marker |

### Local
The user sets `DISPOSABLE_ENVIRONMENT` once per computer:
- `1`: safe to run destructive tests.
- `0`: not safe. Never run destructive tests.
- Not set: never run them. Give the user these commands and ask them to set it.
```
# windows (admin PowerShell)
[Environment]::SetEnvironmentVariable('DISPOSABLE_ENVIRONMENT','0','Machine')

# linux
echo 'DISPOSABLE_ENVIRONMENT=0' | sudo tee -a /etc/environment

# macOS
echo 'export DISPOSABLE_ENVIRONMENT=0' | sudo tee -a /etc/zprofile
```
**Agents must NEVER set `DISPOSABLE_ENVIRONMENT` themselves.**

Once the variable is `1` and the user has approved in the current session, run freely:
```
uv run pytest --run-destructive-local
```

### Remote
A marker on the remote system determines if it's safe to change.
`scripts/mark_remote_disposable.py` creates the marker (only humans may mark).
`tests/verify_remote_disposable.py` checks for the marker on every test run.

**Agents must NEVER run `mark_remote_disposable.py` or mark a remote system as**
**safe to change.**

If the user has approved running destructive tests in the current session, run freely:
```
uv run pytest --run-destructive-remote
```
