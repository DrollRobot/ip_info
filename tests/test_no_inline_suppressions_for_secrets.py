"""Fail the test suite when a detect-secrets allowlist pragma is committed.

Scans every file in the repo for suppression comments -- ``pragma: allowlist
secret`` and its variants -- and fails with the path and line of each one. The
file list comes from ``git ls-files``, so what gets scanned is what
``git add .`` would commit: tracked files plus untracked ones that are not
ignored.

Inline suppressions are prohibited here because they silence a line
permanently, survive edits that change the value underneath them, and leave no
audit trail. Findings belong in ``.secrets.baseline``, where auditing them is
recorded and reviewable.

Escape hatch: :data:`EXEMPT_PATHS`, a whole-file list kept in this source
rather than an inline marker, so granting one shows up in a diff and gets
reviewed. Prose that must quote a pragma verbatim is the expected use.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Keep identical to _PATTERNS in the no-inline-secret-suppressions steering
# hook, if one is installed. Each entry is (compiled pattern,
# human label used in the failure message).
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"pragma:\s*(?:allow|white)list[\s-]+(?:nextline[\s-]+)?secret", re.I),
        "detect-secrets allowlist pragma",
    ),
)

# Repo-relative POSIX paths allowed to contain a suppression string. Add a path
# here only for a file that must quote one verbatim (documentation of this
# rule, a test fixture); never to silence a real finding.
EXEMPT_PATHS: frozenset[str] = frozenset({"AGENTS.md"})

_GUIDANCE = (
    "Inline suppressions are prohibited in this repo -- they silence the line\n"
    "permanently, survive edits that change the value, and leave no audit trail.\n"
    "Record the finding in the baseline and have the user audit it:\n"
    "  uv run detect-secrets scan --baseline .secrets.baseline\n"
)

_THIS_FILE = Path(__file__).resolve()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class GitUnavailableError(RuntimeError):
    """Raised when git cannot list the files that make up the repo."""


@dataclass(frozen=True)
class Hit:
    """One suppression found in one line of one file."""

    path: str
    line_number: int
    label: str
    text: str


def _find_root() -> Path:
    root = _THIS_FILE.parent
    while root != root.parent:
        if (root / "pyproject.toml").exists():
            return root
        root = root.parent
    raise RuntimeError("Could not find project root (no pyproject.toml found)")


_ROOT = _find_root()


def _git_files(root: Path) -> list[Path]:
    """List the files git considers part of the repo.

    Tracked files (``--cached``) plus untracked ones that are not ignored
    (``--others --exclude-standard``), which is exactly the set a ``git add .``
    would commit. Including the untracked half moves the failure to the run
    right after the file is written, rather than the one after it is staged.

    Args:
        root: Project root directory.

    Returns:
        Absolute paths, in git's order.

    Raises:
        GitUnavailableError: If git is not on PATH or ``git ls-files`` fails.
            Never falls back to another file list: a silently different set of
            scanned files is the one failure mode this gate cannot afford.
    """
    git = shutil.which("git")
    if git is None:
        raise GitUnavailableError("git is not on PATH")
    result = subprocess.run(  # noqa: S603  (git path resolved via shutil.which)
        [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitUnavailableError(f"git ls-files exited {result.returncode} in {root}: {detail}")
    names = result.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return [root / name for name in names if name]


def _read_text(path: Path) -> str | None:
    """Return the file's text, or None when it is binary or unreadable."""
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):  # fmt: skip
        return None


def _scan_text(text: str) -> list[tuple[int, str, str]]:
    """Return (line number, label, stripped line) for each suppression in text."""
    found: list[tuple[int, str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for pattern, label in _PATTERNS:
            if pattern.search(line):
                found.append((number, label, line.strip()))
    return found


def _scan_paths(root: Path, paths: list[Path], exempt: frozenset[str]) -> list[Hit]:
    """Scan every readable file in paths, skipping the exempt ones."""
    hits: list[Hit] = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if relative in exempt or not path.is_file():
            continue
        text = _read_text(path)
        if text is None:
            continue
        hits.extend(
            Hit(path=relative, line_number=number, label=label, text=line)
            for number, label, line in _scan_text(text)
        )
    return hits


# Split so this source file never contains an intact suppression comment.
PRAGMA = "# pragma: allow" + "list secret"
PRAGMA_NEXTLINE = "# pragma: allow" + "list nextline secret"
PRAGMA_WHITELIST = "# pragma: white" + "list secret"
PRAGMA_UPPER = "# PRAGMA: ALLOW" + "LIST SECRET"
PRAGMA_NO_SPACE = "# pragma:allow" + "list secret"


# ---------------------------------------------------------------------------
# The CI gate
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.functional
def test_no_inline_suppressions_for_secrets() -> None:
    try:
        paths = _git_files(_ROOT)
    except GitUnavailableError as error:
        pytest.fail(
            f"cannot determine which files belong to the repo: {error}.\n"
            "This gate scans what git would commit and has no fallback file "
            "list on purpose (see this module's docstring). Run it from a git "
            "checkout, with git on PATH.",
            pytrace=False,
        )

    hits = _scan_paths(_ROOT, paths, EXEMPT_PATHS)
    if hits:
        listing = "\n".join(f"  {h.path}:{h.line_number}: {h.label}: {h.text}" for h in hits)
        pytest.fail(
            f"{len(hits)} secret-scanner suppression(s) found "
            f"in the {len(paths)} file(s) git would commit:\n{listing}\n\n{_GUIDANCE}",
            pytrace=False,
        )


@pytest.mark.integration
def test_scan_covers_a_real_file_list() -> None:
    # A gate that silently scans nothing would always pass. This file is in the
    # repo, so its absence means the file list broke.
    assert _THIS_FILE in [p.resolve() for p in _git_files(_ROOT)]


# ---------------------------------------------------------------------------
# The patterns
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "suppression",
    [PRAGMA, PRAGMA_NEXTLINE, PRAGMA_WHITELIST, PRAGMA_UPPER, PRAGMA_NO_SPACE],
)
def test_patterns_flag_known_suppressions(suppression: str) -> None:
    assert _scan_text(f'TOKEN = "abc123"  {suppression}\n')


@pytest.mark.unit
def test_scan_reports_line_and_label() -> None:
    text = f"a = 1\nb = 2\nTOKEN = 'x'  {PRAGMA}\n"
    assert _scan_text(text) == [(3, "detect-secrets allowlist pragma", f"TOKEN = 'x'  {PRAGMA}")]


@pytest.mark.unit
@pytest.mark.parametrize(
    "line",
    [
        "import os  # noqa: F401",
        "# this module handles secret rotation",
        "# nosecrets are stored here",
        "TOKEN = os.environ['TOKEN']",
        "",
    ],
)
def test_clean_lines_are_not_flagged(line: str) -> None:
    assert _scan_text(line) == []


@pytest.mark.unit
def test_this_file_contains_no_intact_suppression() -> None:
    # Guards this file itself: with the steering hook wired, an intact literal
    # in this source would make the file unwritable by any agent.
    assert _scan_text(_THIS_FILE.read_text(encoding="utf-8")) == []


# ---------------------------------------------------------------------------
# File selection
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scan_paths_finds_and_reports_relative_paths(tmp_path: Path) -> None:
    target = tmp_path / "src" / "config.py"
    target.parent.mkdir()
    target.write_text(f"TOKEN = 'x'  {PRAGMA}\n", encoding="utf-8")

    (hit,) = _scan_paths(tmp_path, [target], frozenset())
    assert (hit.path, hit.line_number) == ("src/config.py", 1)


@pytest.mark.unit
def test_exempt_paths_suppress_a_file(tmp_path: Path) -> None:
    target = tmp_path / "docs" / "rule.md"
    target.parent.mkdir()
    target.write_text(f"never write {PRAGMA}\n", encoding="utf-8")

    assert _scan_paths(tmp_path, [target], frozenset()) != []
    assert _scan_paths(tmp_path, [target], frozenset({"docs/rule.md"})) == []


@pytest.mark.unit
def test_binary_and_missing_files_are_skipped(tmp_path: Path) -> None:
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe" + PRAGMA.encode("utf-16"))
    deleted = tmp_path / "gone.py"  # tracked-but-deleted files reach _scan_paths

    assert _scan_paths(tmp_path, [binary, deleted], frozenset()) == []


@pytest.mark.unit
def test_git_files_raises_outside_a_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Fail loudly rather than scanning some other file list: a gate that
    # quietly changes what it covers is worse than one that stops.
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    # git exports its environment to hooks, and in a worktree GIT_DIR is an
    # absolute path, so an inherited one would lead the subprocess back to the
    # repo and this test would never see the failure it is about. Drop only
    # the variables that point git at a repository: clearing the whole GIT_
    # prefix would also drop the discovery bounds and the config paths a
    # container may rely on to declare this checkout safe.
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(GitUnavailableError, match="ls-files exited"):
        _git_files(tmp_path)


@pytest.mark.unit
def test_git_files_raises_when_git_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(GitUnavailableError, match="not on PATH"):
        _git_files(_ROOT)


@pytest.mark.unit
def test_gate_fails_loudly_when_git_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    # The gate must fail, not skip and not pass, when it cannot see the repo.
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(pytest.fail.Exception, match="no fallback file list"):
        test_no_inline_suppressions_for_secrets()
