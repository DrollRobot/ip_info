"""Shared pytest fixtures.

Tests are tagged with the marker taxonomy documented in AGENTS.TESTING.md.
The dependency axis is what gates external resources:

Live tests (marked @pytest.mark.live) require a real external resource --
network, secrets, a live tenant, or a third-party API.
They are configured through the config system (config.toml + the credential
backend; see src/ip_info/config/).
Select on that axis with:

    pytest -m "not live"   # offline tests only (the default pre-commit run)
    pytest -m live         # live tests only
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from ip_info.config import Settings, load_settings
from ip_info.db._initialize_db import ensure_columns_exist, initialize_db

# ---------------------------------------------------------------------------
# Destructive-test opt-in gates
# ---------------------------------------------------------------------------
#
# Destructive tests mutate real state outside a test's own tmp_path and must
# be opted into deliberately. "Local" and "remote" are gated completely
# independently, at both layers, so that clearing one category can never
# accidentally arm the other:
#
#   destructive_local:  mutates the host/device running pytest.
#     Collection gate: --run-destructive-local.
#     Execution gate:  DISPOSABLE_ENVIRONMENT=1, a MACHINE-wide env var --
#     "is this machine disposable" does not depend on which project runs.
#
#   destructive_remote: mutates a remote/external system (cloud resource,
#   database, API tenant, ...).
#     Collection gate: --run-destructive-remote.
#     Execution gate:  tests/verify_remote_disposable.py exits 0. The
#     marker lives ON the remote target itself (see that script's docstring
#     and AGENTS.TESTING.md), not in any local file, so repointing this
#     project's configuration at a different/unmarked target fails closed on
#     its own -- there is nothing local left over to accidentally leave
#     enabled.


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the --run-destructive-local/--run-destructive-remote opt-ins."""
    parser.addoption(
        "--run-destructive-local",
        action="store_true",
        default=False,
        help="collect tests that mutate this host (still requires DISPOSABLE_ENVIRONMENT=1)",
    )
    parser.addoption(
        "--run-destructive-remote",
        action="store_true",
        default=False,
        help=(
            "collect tests that mutate a remote system "
            "(still requires tests/verify_remote_disposable.py to exit 0)"
        ),
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip each destructive category unless its own flag was passed."""
    skip_local = pytest.mark.skip(
        reason="destructive_local: needs --run-destructive-local (disposable host only)"
    )
    skip_remote = pytest.mark.skip(
        reason="destructive_remote: needs --run-destructive-remote (disposable remote target only)"
    )
    run_local = config.getoption("--run-destructive-local")
    run_remote = config.getoption("--run-destructive-remote")
    for item in items:
        if "destructive_local" in item.keywords and not run_local:
            item.add_marker(skip_local)
        if "destructive_remote" in item.keywords and not run_remote:
            item.add_marker(skip_remote)


@pytest.fixture(autouse=True)
def _require_disposable_local(request: pytest.FixtureRequest) -> None:
    """Fail destructive_local tests unless DISPOSABLE_ENVIRONMENT=1 is set.

    Defense-in-depth: --run-destructive-local signals intent, but this guard
    proves the test is running on a host that is safe to mutate. Set
    DISPOSABLE_ENVIRONMENT=1 only in the throwaway VM/container image, never
    on a real workstation.
    """
    if request.node.get_closest_marker("destructive_local") is None:
        return
    # Compare to the literal "1" -- fail-closed. Unset, "0", and any other value
    # all count as non-disposable. Do NOT rewrite this as a truthiness check
    # (`if not os.environ.get(...)`): the string "0" is truthy in Python, so that
    # would arm destructive tests on a host explicitly marked "0" (safe).
    if os.environ.get("DISPOSABLE_ENVIRONMENT") != "1":
        pytest.fail(
            "refusing to run destructive_local test: DISPOSABLE_ENVIRONMENT is not '1' "
            f"(got {os.environ.get('DISPOSABLE_ENVIRONMENT')!r}). This test mutates the "
            "host/device running pytest and must run only on a disposable VM/container.",
            pytrace=False,
        )


@pytest.fixture(scope="session")
def _remote_disposable_confirmed() -> bool:
    """Run tests/verify_remote_disposable.py once per session.

    Session-scoped and lazily materialized: only invoked the first time a
    destructive_remote test actually requests it (see
    _require_disposable_remote), so a session with no destructive_remote
    tests never shells out at all. Re-verifying every session rather than
    caching across runs is deliberate -- a target's disposability can
    change, and a stale "yes" is exactly the failure mode this mechanism
    exists to avoid.
    """
    script = Path(__file__).resolve().parent / "verify_remote_disposable.py"
    if not script.exists():
        return False
    result = subprocess.run(  # noqa: S603 (fixed argv list, no shell)
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode == 0


@pytest.fixture(autouse=True)
def _require_disposable_remote(request: pytest.FixtureRequest) -> None:
    """Fail destructive_remote tests unless the remote target verifies as disposable.

    Defense-in-depth: --run-destructive-remote signals intent, but this guard
    proves the *specific target this project is currently configured to
    point at* has been marked disposable, by asking
    tests/verify_remote_disposable.py -- never by trusting a local file or
    environment variable.
    """
    if request.node.get_closest_marker("destructive_remote") is None:
        return
    if not request.getfixturevalue("_remote_disposable_confirmed"):
        pytest.fail(
            "refusing to run destructive_remote test: tests/verify_remote_disposable.py "
            "did not confirm the remote target as disposable. This test mutates a remote "
            "system and must run only against a target explicitly marked safe (see "
            "scripts/mark_remote_disposable.py and AGENTS.TESTING.md).",
            pytrace=False,
        )


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def settings() -> Settings:
    """Resolved configuration for live tests.

    Resolves through the config system: env vars > credential backend >
    config.toml > schema defaults. Profile selection via the profile env
    var (``resolve.PROFILE_ENV``), else default_profile in config.toml.
    Fails with an actionable ConfigError (naming the init command and env
    vars) when required values are missing.
    """
    return load_settings()


# ---------------------------------------------------------------------------
# Project fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_conn() -> Iterator[sqlite3.Connection]:
    """Return an initialized in-memory cache database, closed after the test."""
    conn = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    initialize_db(conn)
    ensure_columns_exist(conn)
    yield conn
    conn.close()
