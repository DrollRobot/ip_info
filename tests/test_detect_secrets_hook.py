"""Tests for tests/detect_secrets_hook.py, the pre-commit wrapper for detect-secrets.

The regression test reproduces the commit that broke CI's secret scan: every
secret in a file was deleted, and on Windows the plain hook kept that file's
baseline entries because the forward-slash paths pre-commit passes never matched
the baseline's backslash keys. The wrapper must drop them on every platform.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.detect_secrets_hook import native_paths

_ROOT = Path(__file__).resolve().parent.parent
_WRAPPER = _ROOT / "tests" / "detect_secrets_hook.py"
_BASELINE = ".secrets.baseline"

# Exit code detect-secrets-hook returns when it rewrote the baseline.
_BASELINE_UPDATED = 3


def _clean_env() -> dict[str, str]:
    # Under a commit hook git exports GIT_DIR and friends, which would point the
    # git calls below at this repo instead of the temporary one.
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    # A fresh interpreter per call: detect-secrets keeps its settings and the
    # baseline filename in module-level caches that would leak between tests.
    return subprocess.run(  # noqa: S603 -- fixed interpreter and arguments
        [sys.executable, *args],
        cwd=cwd,
        env=_clean_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _git(args: list[str], cwd: Path) -> None:
    git = shutil.which("git")
    assert git, "git is not on PATH"
    subprocess.run(  # noqa: S603 -- resolved git binary, fixed arguments
        [git, *args], cwd=cwd, env=_clean_env(), check=True, capture_output=True, timeout=60
    )


def _baseline_results(repo: Path) -> dict[str, list[dict[str, object]]]:
    results: dict[str, list[dict[str, object]]] = json.loads(
        (repo / _BASELINE).read_text(encoding="utf-8")
    )["results"]
    return results


@pytest.fixture
def repo_with_baselined_secret(tmp_path: Path) -> Path:
    """A git repo whose staged baseline records one secret in ``sub/creds.py``.

    The value is generated per run, so no secret-shaped literal lives in this
    source file. The hook needs a repo: it refuses to run with the baseline
    unstaged.
    """
    _git(["init", "-q"], cwd=tmp_path)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "creds.py").write_text(
        f'api_key = "{secrets.token_hex(20)}"\n', encoding="utf-8"
    )
    scan = _run(["-m", "detect_secrets", "scan", "--all-files"], cwd=tmp_path)
    assert scan.returncode == 0, scan.stderr
    (tmp_path / _BASELINE).write_text(scan.stdout, encoding="utf-8")
    assert _baseline_results(tmp_path), "fixture secret was not detected"
    _git(["add", "-A"], cwd=tmp_path)
    return tmp_path


@pytest.mark.integration
@pytest.mark.regression
def test_entries_for_a_file_with_no_secrets_left_are_dropped(
    repo_with_baselined_secret: Path,
) -> None:
    """Deleting a file's last secret updates the baseline when paths use forward slashes."""
    repo = repo_with_baselined_secret
    (repo / "sub" / "creds.py").write_text("api_key = None\n", encoding="utf-8")

    result = _run([str(_WRAPPER), "--baseline", _BASELINE, "sub/creds.py"], cwd=repo)

    assert result.returncode == _BASELINE_UPDATED, result.stdout + result.stderr
    assert _baseline_results(repo) == {}


@pytest.mark.integration
@pytest.mark.functional
def test_unchanged_secret_passes(repo_with_baselined_secret: Path) -> None:
    """A file whose baselined secret is untouched passes without rewriting the baseline."""
    repo = repo_with_baselined_secret
    before = (repo / _BASELINE).read_text(encoding="utf-8")

    result = _run([str(_WRAPPER), "--baseline", _BASELINE, "sub/creds.py"], cwd=repo)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (repo / _BASELINE).read_text(encoding="utf-8") == before


@pytest.mark.integration
@pytest.mark.functional
def test_new_secret_fails(repo_with_baselined_secret: Path) -> None:
    """A secret missing from the baseline still blocks the commit."""
    repo = repo_with_baselined_secret
    (repo / "sub" / "more.py").write_text(
        f'api_key = "{secrets.token_hex(20)}"\n', encoding="utf-8"
    )

    result = _run([str(_WRAPPER), "--baseline", _BASELINE, "sub/more.py"], cwd=repo)

    assert result.returncode == 1, result.stdout + result.stderr


@pytest.mark.unit
def test_native_paths_converts_existing_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Paths to existing files use the local separator."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.py").write_text("", encoding="utf-8")

    assert native_paths(["sub/a.py"]) == [os.path.join("sub", "a.py")]


@pytest.mark.unit
def test_native_paths_leaves_options_and_patterns_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Options and non-file values such as regexes keep their slashes."""
    monkeypatch.chdir(tmp_path)
    args = ["--baseline", "missing.baseline", "--exclude-files", "docs/.*"]

    assert native_paths(args) == args


@pytest.mark.unit
def test_native_paths_leaves_the_baseline_path_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The --baseline value keeps git's forward slashes for the hook's unstaged check."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / ".secrets.baseline").write_text("{}", encoding="utf-8")
    args = ["--baseline", "sub/.secrets.baseline"]

    assert native_paths(args) == args
