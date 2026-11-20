"""Scans the files git would commit for unwanted string patterns; fails if any are found.

Only tracked files and untracked files not excluded by .gitignore are scanned, so ignored
files (.env files, virtual environments, caches) never match.

If adding sensitive strings that you don't want committed:
- Add .local/ to .gitignore
- Move script to .local/tests
- Create .local/tests/__init__.py
- Update pyproject.toml to include .local/tests in testpaths:
[tool.pytest.ini_options]
testpaths = ["tests",".local/tests"]
- Update pyproject.toml to give .local/tests the same lint exemptions as tests:
[tool.ruff.lint.per-file-ignores]
".local/tests/**" = <same list as "tests/**">

Add regex patterns to UNWANTED_PATTERNS to enable scanning.
Lines matching any EXCEPTION_PATTERNS entry are suppressed (counted but not reported).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.functional]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

UNWANTED_PATTERNS: list[tuple[str, str]] = [
    # ("FIXME", r"#.*\bFIXME\b"),
    # ("TODO",  r"#.*\bTODO\b"),
]

EXCEPTION_PATTERNS: list[str] = [
    r"#\s*noqa:.*unwanted_strings",
]

EXCLUDED_EXTENSIONS: set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".webp",
    ".svg",
    ".zip",
    ".gz",
    ".tar",
    ".7z",
    ".rar",
    ".dll",
    ".exe",
    ".pdb",
    ".bin",
    ".lib",
    ".obj",
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
}

# Git already skips ignored files. List only committed folders and files to skip.
EXCLUDED_FOLDERS: set[str] = set()

EXCLUDED_FILES: set[str] = set()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_root() -> Path:
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "pyproject.toml").exists():
            return p
        p = p.parent
    raise RuntimeError("Could not find project root (no pyproject.toml found)")


_ROOT = _find_root()


def _committable_files() -> list[Path]:
    """List the files git would commit, relative to the project root.

    Covers tracked files plus untracked files that .gitignore does not exclude.

    Returns:
        Sorted relative paths. Tracked files deleted from disk are included; callers
        skip paths that are not regular files.

    Raises:
        RuntimeError: If git is not on PATH or the project root is not in a git repo.
    """
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git not found on PATH; cannot list the files to scan")
    result = subprocess.run(  # noqa: S603 (fixed argv list, no shell)
        [git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {result.stderr.strip()}")
    return sorted({Path(name) for name in result.stdout.split("\0") if name})


@dataclass
class Hit:
    file: str
    line_number: int
    tag: str
    line: str


def _format_table(rows: list[tuple[object, ...]], headers: list[str]) -> str:
    """Render rows as a simple aligned text table (stdlib replacement for tabulate).

    Mirrors tabulate's ``tablefmt="simple"`` layout: a header row, a row of
    dashes underlining each column, then the data rows, with columns left-
    aligned and padded to the widest cell.
    """
    columns = [headers, *([str(cell) for cell in row] for row in rows)]
    widths = [max(len(str(col[i])) for col in columns) for i in range(len(headers))]

    def _line(cells: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()

    lines = [
        _line(headers),
        _line(["-" * w for w in widths]),
        *(_line([str(cell) for cell in row]) for row in rows),
    ]
    return "\n".join(lines)


def _scan() -> tuple[list[Hit], int]:
    compiled_patterns = [(tag, re.compile(pat, re.IGNORECASE)) for tag, pat in UNWANTED_PATTERNS]
    compiled_exceptions = [re.compile(p, re.IGNORECASE) for p in EXCEPTION_PATTERNS]

    hits: list[Hit] = []
    exception_count = 0

    for rel in _committable_files():
        path = _ROOT / rel
        if not path.is_file():
            continue
        if path.suffix in EXCLUDED_EXTENSIONS:
            continue
        if str(rel) in EXCLUDED_FILES:
            continue
        if any(part in EXCLUDED_FOLDERS for part in rel.parts):
            continue

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        for i, line in enumerate(lines, start=1):
            for tag, pattern in compiled_patterns:
                if pattern.search(line):
                    if any(exc.search(line) for exc in compiled_exceptions):
                        exception_count += 1
                        continue
                    hits.append(Hit(file=str(rel), line_number=i, tag=tag, line=line.strip()))

    return hits, exception_count


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


def test_no_unwanted_strings() -> None:
    if not UNWANTED_PATTERNS:
        pytest.skip("No patterns defined.")

    hits, exception_count = _scan()

    if hits:
        table = _format_table(
            [(h.file, h.line_number, h.tag, h.line) for h in hits],
            headers=["File", "Line", "Tag", "Content"],
        )
        summary = f"{len(hits)} match(es), {exception_count} exception(s) suppressed."
        pytest.fail(f"\n{summary}\n\n{table}", pytrace=False)
