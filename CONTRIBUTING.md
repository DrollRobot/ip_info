# Contributing to ip_info

Thank you for your interest in contributing!

## Setting up a development environment

Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/).

```
git clone https://github.com/DrollRobot/ip_info.git
cd ip_info
uv sync --all-groups
uv run pre-commit install
```

## Running checks

The full list of lint, format, type-check, test, and pre-commit commands lives
in [AGENTS.TESTING.md](AGENTS.TESTING.md). Run those before opening a PR.

Pre-commit also runs lint, format, type check, and secret detection
automatically on every commit.

### Docs

```
# live preview at http://127.0.0.1:8000
uv run mkdocs serve

# or build static HTML once
uv run mkdocs build --strict

# deploy to GitHub Pages
uv run mkdocs gh-deploy --force
```

## Project conventions

### Code structure

- `src/ip_info/` -- library source (src layout)
- `src/ip_info/apis/` -- one module per IP-info provider (client + parser)
- `src/ip_info/db/` -- SQLite cache: init, insert, query
- `tests/` -- pytest test suite
- `docs/` -- MkDocs documentation source

### Naming and module conventions

Each provider lives in its own `apis/<provider>.py` module following a
client/parser pattern: it fetches the provider's response and normalizes it
into the shared result shape. Query results are cached in a local SQLite
database (`db/`) so repeated lookups avoid redundant API calls.

### Public API

Export new public symbols from `src/ip_info/__init__.py`.

### Type annotations

All functions must be fully annotated. The package ships a `py.typed` marker,
so downstream consumers depend on its type information.

## Pull requests

1. Branch from `main` and open a PR against `main`.
2. Run the checks and tests in [AGENTS.TESTING.md](AGENTS.TESTING.md) and ensure
   they pass clean.
3. Update `CHANGELOG.md` under `## [Unreleased]`.
4. Update docstrings and `docs/` if the public API changed.

## Reporting issues

Use the GitHub issue templates for bugs and feature requests.
