"""Run the secrets guards the way a commit hook runs them.

git hands its own environment to the hooks it starts, and the variable that
matters is ``GIT_DIR``: once it is set, a git subprocess stops searching for
the repository and trusts the variable instead. In a worktree that value is an
absolute path into the main checkout, so it keeps pointing at a repository from
any directory at all.

Both secrets guards used to let that variable steer the git they called, and
both answered about the wrong directory because of it. The baseline audit asked
``git rev-parse --show-toplevel`` for the repo root and was told ``tests/``, so
it reported ``.secrets.baseline`` missing. The suppression gate ran
``git ls-files`` in an empty temporary directory to prove it fails outside a
repository, and the inherited value led it back to the real one, so it never
failed. Neither showed up in a plain ``pytest`` run -- only at ``git commit``,
where they blocked every commit made from a worktree.

This gate re-runs both guards in a subprocess carrying that environment, so the
next guard that reaches for git without accounting for it fails here, in the
suite, rather than in front of whoever tries to commit next. It sets ``GIT_DIR``
to an absolute path whatever the checkout, so a plain clone exercises the same
condition a worktree does.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# Guard suites to re-run. Each may be absent: a generated project can decline
# the suppression gate at setup time, and the comparison against the template
# expects that, so a missing file is skipped rather than failed.
GUARD_SUITES = (
    "tests/test_secrets_baseline_audited.py",
    "tests/test_no_inline_suppressions_for_secrets.py",
)

# Generous: the guards themselves run in well under a second, so anything near
# this means the subprocess is stuck rather than slow.
_TIMEOUT_SECONDS = 300


def _find_root() -> Path:
    """Locate the repository root by walking up to the ``pyproject.toml`` marker.

    Uses the same marker walk the guards use, deliberately: asking git here
    would reintroduce the dependency this module exists to catch.
    """
    root = Path(__file__).resolve().parent
    while root != root.parent:
        if (root / "pyproject.toml").exists():
            return root
        root = root.parent
    raise RuntimeError("Could not find project root (no pyproject.toml found)")


_ROOT = _find_root()


def _absolute_git_dir(git: str) -> str:
    """Return this checkout's git directory as an absolute path.

    Raises:
        RuntimeError: If git cannot answer, which means the environment this
            gate is trying to simulate cannot be described.
    """
    result = subprocess.run(  # noqa: S603  (git path resolved via shutil.which)
        [git, "rev-parse", "--absolute-git-dir"],
        cwd=_ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git rev-parse --absolute-git-dir failed: {detail}")
    return result.stdout.decode("utf-8", errors="replace").strip()


def _hook_environment(git: str) -> dict[str, str]:
    """Return this process's environment plus the variables git exports to hooks.

    ``GIT_DIR`` is the one that misleads a subprocess, and it is absolute here
    whatever the checkout, so the condition a worktree creates is reproduced in
    a plain clone too. ``GIT_INDEX_FILE`` comes along because git sets it for
    the same hooks and a guard could just as easily be steered by it.
    """
    git_dir = _absolute_git_dir(git)
    env = os.environ.copy()
    env["GIT_DIR"] = git_dir
    env["GIT_INDEX_FILE"] = str(Path(git_dir) / "index")
    return env


@pytest.mark.integration
@pytest.mark.regression
def test_secrets_guards_pass_under_a_hook_environment() -> None:
    """Both secrets guards pass with git's hook variables set.

    Failure here means a guard is trusting the git environment it inherits and
    will misfire inside a commit hook -- most visibly from a worktree, where
    ``GIT_DIR`` is absolute.
    """
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")

    suites = [name for name in GUARD_SUITES if (_ROOT / name).exists()]
    if not suites:
        pytest.skip("no secrets guard suites present in this project")

    result = subprocess.run(  # noqa: S603  (interpreter path from sys.executable)
        [sys.executable, "-m", "pytest", *suites, "--no-cov", "-q", "-p", "no:cacheprovider"],
        cwd=_ROOT,
        env=_hook_environment(git),
        capture_output=True,
        check=False,
        timeout=_TIMEOUT_SECONDS,
    )

    if result.returncode != 0:
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        pytest.fail(
            "The secrets guards fail when git's hook variables are set, so they "
            "will fail the next commit made from a worktree.\n"
            f"Suites: {', '.join(suites)}\n"
            f"pytest exited {result.returncode}.\n\n{stdout}\n{stderr}",
            pytrace=False,
        )
