"""Fail the test suite when a repo file holds a non-ASCII character.

Every text file in the repo is ASCII only. Besides stray long dashes and curly
quotes, this blocks characters that hide what code does: bidirectional
controls (Trojan Source, CVE-2021-42574) and look-alike letters.

The file list comes from ``git ls-files``, so what gets scanned is what
``git add .`` would commit: tracked files plus untracked ones that are not
ignored. Caches and other ignored files are never scanned. A file with a NUL
byte in its first 8000 bytes is binary, by git's own rule, and skipped. A text
file that is not valid UTF-8 is still scanned, and each byte that does not
decode is reported.

Escape hatch: :data:`EXEMPT_PATHS`, a whole-file list kept in this source, so
granting one shows up in a diff and gets reviewed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

import pytest

# Repo-relative POSIX paths allowed to hold non-ASCII characters. Add a path
# here only for a file that must, such as a test fixture for Unicode handling.
EXEMPT_PATHS: frozenset[str] = frozenset(
    {
        "src/ip_info/iso_country_codes.csv",  # official country names carry accents
    }
)

_GUIDANCE = (
    "Repo files are ASCII only. Replace each character with its ASCII form:\n"
    "  long dash -> -    curly quotes -> ' or \"    ellipsis -> ...    arrow -> ->\n"
    "A byte marked 'not UTF-8': re-save the file as UTF-8, then fix what remains.\n"
)

# git calls a file binary when a NUL byte appears in its first 8000 bytes.
_BINARY_SNIFF_BYTES = 8000

_THIS_FILE = Path(__file__).resolve()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class GitUnavailableError(RuntimeError):
    """Raised when git cannot list the files that make up the repo."""


@dataclass(frozen=True)
class Hit:
    """One non-ASCII character found in one line of one file."""

    path: str
    line_number: int
    column: int
    char: str


def _find_root() -> Path:
    """Return the project root: the nearest folder above this file with a pyproject.toml.

    Raises:
        RuntimeError: No folder above this file holds a pyproject.toml.
    """
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
    (``--others --exclude-standard``): the set a ``git add .`` would commit.

    Args:
        root: Project root directory.

    Returns:
        Absolute paths, in git's order.

    Raises:
        GitUnavailableError: git is not on PATH, or ``git ls-files`` fails.
            Never falls back to another file list, so the gate cannot quietly
            scan a different set of files.
    """
    git = shutil.which("git")
    if git is None:
        raise GitUnavailableError("git is not on PATH")
    result = subprocess.run(  # noqa: S603 - resolved git binary, fixed arguments
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
    """Return the file's text, or None when it is binary or unreadable.

    Bytes that are not valid UTF-8 become lone surrogates (``surrogateescape``)
    instead of making the file count as binary, so a text file saved in a
    legacy encoding such as cp1252 is scanned, not skipped.

    Args:
        path: The file to read.

    Returns:
        The decoded text, or None for a binary or unreadable file.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:_BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="surrogateescape")


def _scan_text(text: str) -> list[tuple[int, int, str]]:
    """Find each non-ASCII character in ``text``.

    Lines split on newlines only. ``str.splitlines`` also splits on, and drops,
    U+2028, U+2029 and U+0085, so the scan would miss them; and it splits on
    form feeds, so line numbers would not match an editor's.

    Args:
        text: A file's contents.

    Returns:
        ``(line number, column, character)`` for each one, both numbers counted from 1.
    """
    return [
        (number, column, char)
        for number, line in enumerate(text.split("\n"), start=1)
        for column, char in enumerate(line, start=1)
        if not char.isascii()
    ]


def _scan_paths(root: Path, paths: list[Path], exempt: frozenset[str]) -> list[Hit]:
    """Scan every readable text file in ``paths``, skipping the exempt ones.

    Args:
        root: Project root, for the repo-relative paths in each hit.
        paths: Absolute paths of the files to scan.
        exempt: Repo-relative POSIX paths to skip.

    Returns:
        Every non-ASCII character found.
    """
    hits: list[Hit] = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if relative in exempt or not path.is_file():
            continue
        text = _read_text(path)
        if text is None:
            continue
        hits.extend(
            Hit(path=relative, line_number=number, column=column, char=char)
            for number, column, char in _scan_text(text)
        )
    return hits


def _describe(char: str) -> str:
    """Name a character for the failure message, e.g. ``U+2014 EM DASH``.

    A lone surrogate from U+DC80 to U+DCFF stands for a byte that is not valid
    UTF-8 (see :func:`_read_text`), and is named as that byte.

    Args:
        char: One character.

    Returns:
        The character's code point and Unicode name, or the byte it stands for.
    """
    code = ord(char)
    if 0xDC80 <= code <= 0xDCFF:
        return f"byte 0x{code - 0xDC00:02X} (not UTF-8)"
    return f"U+{code:04X} {unicodedata.name(char, 'UNNAMED')}"


# ---------------------------------------------------------------------------
# The CI gate
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.functional
def test_repo_files_are_ascii_only() -> None:
    """Every text file git would commit holds only ASCII characters."""
    try:
        paths = _git_files(_ROOT)
    except GitUnavailableError as error:
        pytest.fail(
            f"cannot determine which files belong to the repo: {error}.\n"
            "This gate scans what git would commit and has no fallback file "
            "list on purpose. Run it from a git checkout, with git on PATH.",
            pytrace=False,
        )

    hits = _scan_paths(_ROOT, paths, EXEMPT_PATHS)
    if hits:
        listing = "\n".join(
            f"  {h.path}:{h.line_number}:{h.column}: {_describe(h.char)}" for h in hits
        )
        pytest.fail(
            f"{len(hits)} non-ASCII character(s) found "
            f"in the {len(paths)} file(s) git would commit:\n{listing}\n\n{_GUIDANCE}",
            pytrace=False,
        )


@pytest.mark.integration
def test_scan_covers_a_real_file_list() -> None:
    """The real file list includes this file.

    A gate that silently scans nothing would always pass, so this file's
    absence means the file list broke.
    """
    assert _THIS_FILE in [p.resolve() for p in _git_files(_ROOT)]


@pytest.mark.unit
def test_gate_fails_loudly_when_git_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate fails, rather than skips or passes, when it cannot see the repo."""
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(pytest.fail.Exception, match="no fallback file list"):
        test_repo_files_are_ascii_only()


# ---------------------------------------------------------------------------
# The gate, run against a throwaway repo
# ---------------------------------------------------------------------------


@pytest.fixture
def git_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty git repo whose ``.gitignore`` ignores ``ignored/``.

    Under a commit hook git exports ``GIT_DIR`` and friends, which would point
    git at this repo instead of the temporary one, so every ``GIT_`` variable
    is removed. The user's and the system's git config are shut out too: a
    global ignore file would change which files git lists.
    """
    for name in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    git = shutil.which("git")
    assert git, "git is not on PATH"
    subprocess.run(  # noqa: S603 - resolved git binary, fixed arguments
        [git, "init", "-q"], cwd=tmp_path, check=True, capture_output=True, timeout=60
    )
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    return tmp_path


@pytest.mark.integration
def test_git_files_lists_untracked_files_but_not_ignored_ones(git_repo: Path) -> None:
    """The file list is what ``git add .`` would commit."""
    (git_repo / "new.md").write_text("new\n", encoding="utf-8")
    (git_repo / "ignored").mkdir()
    (git_repo / "ignored" / "cache.txt").write_text("caf\u00e9\n", encoding="utf-8")

    listed = {path.relative_to(git_repo).as_posix() for path in _git_files(git_repo)}

    assert listed == {".gitignore", "new.md"}


@pytest.mark.integration
@pytest.mark.functional
def test_gate_reports_each_hit(git_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate fails on a non-ASCII character and names its file, line, column and code."""
    (git_repo / "a.md").write_text("ok\nnot \u2014 ok\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "_ROOT", git_repo)

    with pytest.raises(pytest.fail.Exception, match=r"a\.md:2:5: U\+2014 EM DASH"):
        test_repo_files_are_ascii_only()


@pytest.mark.integration
@pytest.mark.functional
def test_gate_passes_an_ascii_repo(git_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate passes when every file git would commit is ASCII."""
    (git_repo / "a.md").write_text("plain ascii\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "_ROOT", git_repo)

    test_repo_files_are_ascii_only()


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "char", ["\u2014", "\u2018", "\u201c", "\u2026", "\u00e9", "\u00a0", "\u202e", "\u0430"]
)
def test_scan_flags_non_ascii_characters(char: str) -> None:
    """Common stray characters, a bidi override and a look-alike letter are flagged."""
    assert _scan_text(f"a {char} b\n") == [(1, 3, char)]


@pytest.mark.unit
@pytest.mark.regression
@pytest.mark.parametrize("char", ["\u2028", "\u2029", "\x85"])
def test_scan_flags_line_separators(char: str) -> None:
    """Unicode line separators are flagged, not taken as line breaks and dropped."""
    assert _scan_text(f"a{char}b\n") == [(1, 2, char)]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ascii\nab\u2014c\n", [(2, 3, "\u2014")]),
        ("a\r\nb\u2014\r\n", [(2, 2, "\u2014")]),
        ("a\x0cb\n\u2014\n", [(2, 1, "\u2014")]),
    ],
    ids=["lf", "crlf", "form-feed"],
)
def test_scan_reports_line_and_column(text: str, expected: list[tuple[int, int, str]]) -> None:
    """Line numbers count newlines only, as an editor does."""
    assert _scan_text(text) == expected


@pytest.mark.unit
def test_plain_ascii_is_not_flagged() -> None:
    """No ASCII character is flagged, control characters included."""
    every_ascii = "".join(chr(code) for code in range(128))
    assert _scan_text(every_ascii) == []


@pytest.mark.unit
def test_describe_names_the_character() -> None:
    """A character is named by its code point and Unicode name."""
    assert _describe("\u2014") == "U+2014 EM DASH"


@pytest.mark.unit
def test_describe_names_a_byte_that_is_not_utf8() -> None:
    """A byte that did not decode is named as that byte."""
    assert _describe("\udc93") == "byte 0x93 (not UTF-8)"


# ---------------------------------------------------------------------------
# File selection
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scan_paths_reports_relative_paths(tmp_path: Path) -> None:
    """Hits carry repo-relative POSIX paths."""
    target = tmp_path / "docs" / "a.md"
    target.parent.mkdir()
    target.write_text("ok\nnot \u2014 ok\n", encoding="utf-8")

    assert _scan_paths(tmp_path, [target], frozenset()) == [
        Hit(path="docs/a.md", line_number=2, column=5, char="\u2014")
    ]


@pytest.mark.unit
def test_text_that_is_not_utf8_is_scanned(tmp_path: Path) -> None:
    """A cp1252 file's curly quotes are flagged, not skipped as binary."""
    target = tmp_path / "legacy.md"
    target.write_bytes("say \u201chi\u201d\n".encode("cp1252"))

    assert _scan_paths(tmp_path, [target], frozenset()) == [
        Hit(path="legacy.md", line_number=1, column=5, char="\udc93"),
        Hit(path="legacy.md", line_number=1, column=8, char="\udc94"),
    ]


@pytest.mark.unit
def test_exempt_paths_skip_a_file(tmp_path: Path) -> None:
    """A path in the exempt list is not scanned."""
    target = tmp_path / "fixture.txt"
    target.write_text("caf\u00e9\n", encoding="utf-8")

    assert _scan_paths(tmp_path, [target], frozenset()) != []
    assert _scan_paths(tmp_path, [target], frozenset({"fixture.txt"})) == []


@pytest.mark.unit
def test_binary_and_missing_files_are_skipped(tmp_path: Path) -> None:
    """Binary files and tracked-but-deleted files are skipped."""
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe")
    deleted = tmp_path / "gone.py"  # tracked-but-deleted files reach _scan_paths

    assert _scan_paths(tmp_path, [binary, deleted], frozenset()) == []
