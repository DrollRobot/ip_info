# Agent testing instructions

```
# if pyproject.toml was changed:
uv sync                               # after pyproject.toml edits
uv lock --check                       # verify lockfile in sync

# code checks and formatting
uv run ruff check .                   # lint
uv run ruff format .                  # apply ruff formatting
uv run mypy                           # type check (targets set in pyproject.toml)

# tests
uv run pytest -m "not integration"    # offline tests
uv run pytest                         # online and offline tests (when credentialed)

# dependency CVE audit (network; OSV database) -- also gated in CI via audit.yml
uv audit

# docs build catches broken refs/nav and docstring import errors
uv run mkdocs build --strict

# run every pre-commit hook across the repo (lint, format, type, secret scan)
uv run pre-commit run --all-files
```
