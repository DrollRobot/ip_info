"""Live: scripts/wait_for_ci.py against this repository on GitHub. It only reads.

Run with:  uv run pytest -m live tests/test_live_wait_for_ci.py -s --no-cov

The commit checked is the upstream branch's, which GitHub has. Whether its jobs passed is not
the script's business, so either verdict passes; what must hold is that a verdict comes back.
"""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = [pytest.mark.live, pytest.mark.e2e, pytest.mark.slow]

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


@pytest.fixture
def ci(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """The script as a module."""
    monkeypatch.syspath_prepend(str(SCRIPTS))
    return importlib.import_module("wait_for_ci")


def run(*args: str) -> subprocess.CompletedProcess[str]:
    """Run a command found on PATH, without a shell."""
    program = shutil.which(args[0])
    if program is None:
        pytest.skip(f"{args[0]} is not installed")
    return subprocess.run(  # noqa: S603 (program path from shutil.which, fixed arguments)
        [program, *args[1:]], capture_output=True, text=True, encoding="utf-8", check=False
    )


@pytest.fixture
def pushed() -> str:
    """The upstream branch's commit; skips when the branch has no upstream."""
    result = run("git", "rev-parse", "@{upstream}")
    if result.returncode != 0:
        pytest.skip("the branch has no upstream")
    return result.stdout.strip()


@pytest.fixture
def private() -> bool:
    """Whether GitHub says this repository is private, asked through gh; skips without gh."""
    result = run("gh", "repo", "view", "--json", "isPrivate")
    if result.returncode != 0:
        pytest.skip("gh cannot read this repository")
    return bool(json.loads(result.stdout)["isPrivate"])


@pytest.mark.usefixtures("private")  # skips unless gh can read the repository
def test_through_gh_a_verdict_comes_back(
    ci: ModuleType, pushed: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code = ci.main(["--sha", pushed])

    out, err = capsys.readouterr()
    print(err + out)
    assert "through gh, checking every 10 s" in err
    assert code in (ci.EXIT_PASSED, ci.EXIT_FAILED), out
    assert out.strip().splitlines()[-1].startswith(("RESULT: PASSED", "RESULT: FAILED"))


def test_signed_out_reads_a_public_repository_and_refuses_a_private_one(
    ci: ModuleType,
    pushed: str,
    private: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    git = shutil.which("git")
    monkeypatch.setattr(ci.shutil, "which", lambda name: git if name == "git" else None)

    code = ci.main(["--sha", pushed])

    out, err = capsys.readouterr()
    print(err + out)
    assert "gh is not installed; reading GitHub signed out." in err
    if private:
        assert code == ci.EXIT_ERROR
        assert "is private or does not exist" in out
    else:
        assert code in (ci.EXIT_PASSED, ci.EXIT_FAILED), out
        assert "through the GitHub API (signed out), checking every 60 s" in err
