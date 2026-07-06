"""Compare a project's baseline files against the template it was created from.

A project generated from this template keeps a set of "baseline" files that
should track the template as it evolves: the GitHub workflows and templates,
the dev helper scripts, the AGENTS docs, lint/format config, and so on. This
script compares those files between a template checkout and the project,
replaying the mechanical transformations the template-setup scripts performed
so that only real drift is reported:

  - the template's snake_case / kebab-case project name -> the project's names
  - the template author's GitHub username -> the project's (from `git remote`)
  - the "TEMPLATE SETUP NOTES" banner comments -> stripped from both sides
  - the pinned Python version -> the project's (from `.python-version`)
  - the template-only pyproject.toml config -> dropped, as cleanup.py does

Each baseline file is strict (drift is an error) or lenient (expected to
diverge; reported for review only), and required or optional (optional
features such as mkdocs or the credential helpers may be deleted from a
project). Files the project adds on top of the template are ignored.

Before comparing, the script checks its own version on both sides and offers
to update the project's copy from the template when they differ, so the
manifest it compares against is the template's current one.

Run it from either repository; the other repository is given as the
positional path (default: a sibling folder with the template's name):

    uv run scripts/compare_to_template.py
    uv run scripts/compare_to_template.py C:/dev/TEMPLATE-CLONE
    uv run scripts/compare_to_template.py --diff        # show unified diffs
    uv run scripts/compare_to_template.py --all         # also list matching files
    uv run scripts/compare_to_template.py --no-update   # CI: never write anything

Exit codes: 0 = no drift (lenient "review" differences allowed), 1 = drift
found (a strict file differs or a required file is missing) or a fatal error.
"""

from __future__ import annotations

import argparse
import difflib
import re
import shutil
import sys
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatch
from os.path import normcase, normpath
from pathlib import Path

import _cli as cli

# Version of this helper script itself. Bump on every change so copies in other
# repos can be compared: patch = bugfix, minor = new flag/behavior, major =
# breaking CLI change.
__version__ = "1.0.0"

# The template's identity tokens. Built from pieces so that a child project's
# rename_project.py / set_github_user.py runs (which string-replace these
# tokens across every text file) leave this script functional: the constants
# must keep their template-side values in every copy of this file.
TEMPLATE_SNAKE = "_".join(("python", "repo", "template"))
TEMPLATE_KEBAB = "-".join(("python", "repo", "template"))
TEMPLATE_USER = "".join(("droll", "robot"))

# This script's own path, used by the self-check/update step.
SELF_REL = "scripts/compare_to_template.py"

# The template-header banner marker (see scripts/template_setup/
# strip_template_headers.py). Assigning it here is safe: the strip script only
# removes the marker when it sits inside a comment banner.
_MARKER = "TEMPLATE SETUP NOTES"

# A banner separator line such as "# ====" or "// ====".
_SEP_RE = re.compile(r"^\s*(?:#|//)\s*=+\s*$")

_VERSION_RE = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.MULTILINE)

# MAJOR.MINOR or MAJOR.MINOR.PATCH, as accepted by set_python_version.py.
_PY_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)*$")


@dataclass(frozen=True)
class BaselineFile:
    """One template file tracked by the comparison.

    Attributes:
        path: Template-relative POSIX path.
        required: Whether the file must exist in the project (``False`` for
            deletable optional features).
        strict: Whether content drift is an error (``False`` for files that
            are expected to diverge and are reported for review only).
    """

    path: str
    required: bool = True
    strict: bool = True


# Every tracked template file is either listed here or matched by the
# exclusion lists below; tests/test_compare_to_template.py enforces that, so
# adding a file to the template forces a decision about how to compare it.
MANIFEST: tuple[BaselineFile, ...] = (
    # GitHub configuration: identical apart from the name/user rename.
    BaselineFile(".github/ISSUE_TEMPLATE/bug_report.yml"),
    BaselineFile(".github/ISSUE_TEMPLATE/config.yml"),
    BaselineFile(".github/ISSUE_TEMPLATE/feature_request.yml"),
    BaselineFile(".github/PULL_REQUEST_TEMPLATE.md"),
    BaselineFile(".github/dependabot.yml"),
    BaselineFile(".github/workflows/audit.yml"),
    BaselineFile(".github/workflows/ci.yml"),
    BaselineFile(".github/workflows/docs.yml", required=False),  # mkdocs feature
    # Claude Code configuration. choose_shell.py deletes the unchosen hook
    # pair (or all hooks), and settings.json accumulates per-project
    # permissions, so the hooks are optional and the settings are lenient.
    BaselineFile(".claude/hooks/canonical-commands-bash.py", required=False),
    BaselineFile(".claude/hooks/canonical-commands-pwsh.py", required=False),
    BaselineFile(".claude/hooks/no-chained-commands-bash.py", required=False),
    BaselineFile(".claude/hooks/no-chained-commands-pwsh.py", required=False),
    BaselineFile(".claude/hooks/protect-auto-memory.py", required=False),
    BaselineFile(".claude/settings.json", required=False, strict=False),
    # Editor / lint / format / hygiene config.
    BaselineFile(".editorconfig"),
    BaselineFile(".gitattributes"),
    BaselineFile(".pre-commit-config.yaml"),
    BaselineFile(".gitignore", strict=False),  # projects append their own ignores
    BaselineFile(".env.example", required=False, strict=False),  # project env vars
    # Agent and contributor docs.
    BaselineFile("AGENTS.md", strict=False),  # holds the project's own rules
    BaselineFile("AGENTS.RELEASING.md"),
    BaselineFile("AGENTS.TESTING.md"),
    BaselineFile("AGENTS.WORKTREE.md"),
    BaselineFile("CLAUDE.md"),
    BaselineFile("CONTRIBUTING.md"),
    BaselineFile("SECURITY.md"),
    BaselineFile("README.md", strict=False),  # rewritten per project
    # Project configuration: always diverges (version, description, deps).
    BaselineFile("pyproject.toml", strict=False),
    # Dev helper scripts (each carries its own __version__).
    BaselineFile("scripts/_cli.py"),
    BaselineFile(SELF_REL),
    BaselineFile("scripts/complete_worktree.py"),
    BaselineFile("scripts/new_worktree.py"),
    BaselineFile("scripts/push_new_tag_to_main.py"),
    BaselineFile("scripts/remove_worktree.py"),
    BaselineFile("scripts/setup_credentials.py", required=False),  # credentials feature
    # Documentation site (mkdocs feature; content is the project's own).
    BaselineFile("mkdocs.yml", required=False, strict=False),
    BaselineFile("docs/index.md", required=False, strict=False),
    BaselineFile(f"docs/reference/{TEMPLATE_SNAKE}.md", required=False, strict=False),
    # Test infrastructure (credential feature is removable; conftest grows
    # project fixtures).
    BaselineFile("tests/__init__.py", required=False),
    BaselineFile("tests/conftest.py", required=False, strict=False),
    BaselineFile("tests/_bootstrap.py", required=False),
    BaselineFile("tests/_keyvault.py", required=False),
)

# Tracked template paths deliberately not compared. Prefixes cover the
# project's own source and the setup scripts (deleted by cleanup.py); globs
# cover per-project files and the template-development test suite (also
# deleted by cleanup.py).
EXCLUDED_PREFIXES = ("src/", "scripts/template_setup/")
EXCLUDED_GLOBS = (
    "CHANGELOG.md",
    "CHANGELOG.md.FIXME",
    "LICENSE.*.FIXME",
    "uv.lock",
    ".python-version",  # compared indirectly: replayed onto the template side
    "*.code-workspace.FIXME.jsonc",
    "tests/test_*.py",
)

# Strict files that remove_mkdocs.py edits in place; when the project has
# removed mkdocs they are compared leniently instead, because the template
# side still carries the mkdocs sections.
MKDOCS_EDITED = ("CONTRIBUTING.md", "AGENTS.RELEASING.md")


@dataclass(frozen=True)
class ProjectNames:
    """The project-side values of the template's identity tokens.

    Attributes:
        snake: The project's snake_case import/package name.
        kebab: The project's kebab-case distribution name.
        github_user: The project's GitHub username, or ``None`` when it could
            not be determined (username differences are then not normalized).
    """

    snake: str
    kebab: str
    github_user: str | None


@dataclass(frozen=True)
class CompareContext:
    """Everything :func:`compare_one` needs to compare one baseline file.

    Attributes:
        template_root: Root of the template checkout.
        project_root: Root of the project checkout.
        names: Project-side identity tokens.
        dotted: Project Python version as ``MAJOR.MINOR``, or ``None`` to skip
            Python-version normalization.
        compact: Project Python version as ``pyMAJORMINOR``, or ``None``.
        ran_cleanup: Whether the project ran cleanup.py (its template-only
            pyproject.toml lines are then dropped from the template side too).
        has_mkdocs: Whether the project still has mkdocs (``mkdocs.yml``
            present); when ``False`` the :data:`MKDOCS_EDITED` files are
            compared leniently.
    """

    template_root: Path
    project_root: Path
    names: ProjectNames
    dotted: str | None
    compact: str | None
    ran_cleanup: bool
    has_mkdocs: bool


@dataclass(frozen=True)
class Comparison:
    """The comparison result for one baseline file.

    Attributes:
        entry: The manifest entry that was compared.
        project_rel: The project-relative path (differs from ``entry.path``
            when the path itself contains the project name).
        status: One of ``match``, ``modified``, ``review``, ``missing``,
            ``absent``, or ``no-template``.
        note: Extra detail appended to the report line.
        template_norm: Normalized template text (for ``--diff``), if any.
        project_norm: Normalized project text (for ``--diff``), if any.
    """

    entry: BaselineFile
    project_rel: str
    status: str
    note: str = ""
    template_norm: str | None = None
    project_norm: str | None = None


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested in tests/test_compare_to_template.py)
# ---------------------------------------------------------------------------


def is_excluded(rel: str) -> bool:
    """Return whether a tracked template path is deliberately not compared.

    Args:
        rel: Template-relative POSIX path.

    Returns:
        ``True`` if the path is covered by the exclusion lists.
    """
    if rel.startswith(EXCLUDED_PREFIXES):
        return True
    return any(fnmatch(rel, pattern) for pattern in EXCLUDED_GLOBS)


def normalize_eol(text: str) -> str:
    """Normalize CRLF/CR line endings to LF so checkouts compare equal.

    Args:
        text: File contents.

    Returns:
        The contents with every line ending as a bare LF.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n")


def strip_template_header(text: str) -> str:
    """Remove the template's "setup notes" banner from ``text``, if present.

    Mirrors scripts/template_setup/strip_template_headers.py: the banner is
    the separator-delimited comment block (hash, slash, or Markdown style)
    around the marker line, plus one run of trailing blank lines.

    Args:
        text: File contents.

    Returns:
        The contents without the banner, or unchanged when there is none.
    """
    lines = text.splitlines(keepends=True)
    marker_index = next((i for i, line in enumerate(lines) if _MARKER in line), None)
    if marker_index is None:
        return text

    marker_line = lines[marker_index].lstrip()
    if marker_line.startswith(("#", "//")):
        prefix = "#" if marker_line.startswith("#") else "//"
        top = marker_index
        while top - 1 >= 0 and lines[top - 1].lstrip().startswith(prefix):
            top -= 1
        bottom = marker_index
        while bottom + 1 < len(lines) and lines[bottom + 1].lstrip().startswith(prefix):
            bottom += 1
        separators = [i for i in range(top, bottom + 1) if _SEP_RE.match(lines[i])]
        if not separators:
            return text
        start, end = separators[0], separators[-1]
    else:
        start = marker_index
        while start >= 0 and "<!--" not in lines[start]:
            start -= 1
        end = marker_index
        while end < len(lines) and "-->" not in lines[end]:
            end += 1
        if start < 0 or end >= len(lines):
            return text

    stop = end + 1
    while stop < len(lines) and not lines[stop].strip():
        stop += 1
    del lines[start:stop]
    return "".join(lines)


def script_version(text: str) -> str | None:
    """Extract a helper script's ``__version__`` string.

    Args:
        text: The script's source text.

    Returns:
        The version string, or ``None`` when the script declares none.
    """
    match = _VERSION_RE.search(text)
    return match.group(1) if match else None


def version_tuple(version: str) -> tuple[int, ...] | None:
    """Parse a dotted version string into a comparable tuple of ints.

    Args:
        version: Version string such as ``"1.2.3"``.

    Returns:
        The numeric parts, or ``None`` when any part is not an integer.
    """
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return None


def python_version_forms(version: str) -> tuple[str, str, str]:
    """Derive the three spellings of a Python version used across the project.

    Mirrors scripts/template_setup/set_python_version.py.

    Args:
        version: Version string (``MAJOR.MINOR`` or ``MAJOR.MINOR.PATCH``).

    Returns:
        A ``(full, dotted, compact)`` tuple, e.g. ``("3.14.3", "3.14", "py314")``.

    Raises:
        ValueError: If ``version`` is not a valid Python version string.
    """
    cleaned = version.strip()
    match = _PY_VERSION_RE.match(cleaned)
    if not match:
        raise ValueError(f"'{version}' is not a valid Python version.")
    major, minor = match.group(1), match.group(2)
    return cleaned, f"{major}.{minor}", f"py{major}{minor}"


def github_user_from_url(url: str) -> str | None:
    """Extract the GitHub username from a remote URL.

    Handles ``https://github.com/USER/...``, ``git@github.com:USER/...``, and
    ``ssh://git@github.com/USER/...`` forms. Non-GitHub remotes yield ``None``.

    Args:
        url: The remote URL.

    Returns:
        The username, or ``None`` when it cannot be determined.
    """
    match = re.search(r"github\.com[:/]([A-Za-z0-9-]+)/", url)
    return match.group(1) if match else None


def replace_case_insensitive(text: str, old: str, new: str) -> str:
    """Replace every occurrence of ``old`` (any case) with ``new``.

    Args:
        text: Text to rewrite.
        old: Substring to find, case-insensitively.
        new: Literal replacement.

    Returns:
        The rewritten text.
    """
    return re.sub(re.escape(old), lambda _match: new, text, flags=re.IGNORECASE)


def replay_python_version(rel: str, text: str, dotted: str, compact: str) -> str:
    """Rewrite the template's Python version pins to the project's version.

    Applies the same targeted edits as set_python_version.py so a project on a
    different Python version does not read as drift. Files the setup script
    does not touch are returned unchanged.

    Args:
        rel: Template-relative path of the file.
        text: Template-side file contents.
        dotted: Project Python version as ``MAJOR.MINOR``.
        compact: Project Python version as ``pyMAJORMINOR``.

    Returns:
        The rewritten contents.
    """
    if rel == "pyproject.toml":
        text = re.sub(r'(requires-python\s*=\s*">=\s*)\d+\.\d+(?:\.\d+)*', rf"\g<1>{dotted}", text)
        text = re.sub(r'(target-version\s*=\s*")py\d+(")', rf"\g<1>{compact}\g<2>", text)
        text = re.sub(
            r'(python_version\s*=\s*")\d+\.\d+(?:\.\d+)*(")', rf"\g<1>{dotted}\g<2>", text
        )
    elif rel == ".pre-commit-config.yaml":
        text = re.sub(r"(python:\s*python)\d+\.\d+(?:\.\d+)*", rf"\g<1>{dotted}", text)
    elif rel == "CONTRIBUTING.md":
        text = re.sub(r"(Python\s+)\d+\.\d+(?:\.\d+)*\+", rf"\g<1>{dotted}+", text)
    elif rel == "README.md":
        text = re.sub(r"(badge/python-)\d+\.\d+(?:\.\d+)*(%2B)", rf"\g<1>{dotted}\g<2>", text)
    elif rel == ".github/ISSUE_TEMPLATE/bug_report.yml":
        text = re.sub(
            r'(id:\s*python-version\b[\s\S]*?placeholder:\s*")\d+\.\d+', rf"\g<1>{dotted}", text
        )
    return text


def replay_cleanup_pyproject(text: str) -> str:
    """Drop the template-only pyproject.toml lines, as cleanup.py does.

    Tolerates missing snippets (unlike cleanup.py) because the comparison
    still works either way; the difference simply shows up in the diff.

    Args:
        text: Template-side pyproject.toml contents (LF line endings).

    Returns:
        The trimmed contents.
    """
    text = text.replace('    "--cov=scripts",\n', "")
    return text.replace(
        'mypy_path = ["scripts", "scripts/template_setup"]', 'mypy_path = ["scripts"]'
    )


def map_project_path(rel: str, names: ProjectNames) -> str:
    """Map a template-relative path to its project-relative counterpart.

    Paths that embed the template name (e.g. the docs API-reference page) were
    renamed by rename_project.py; everything else maps to itself.

    Args:
        rel: Template-relative POSIX path.
        names: Project-side identity tokens.

    Returns:
        The project-relative POSIX path.
    """
    return rel.replace(TEMPLATE_SNAKE, names.snake).replace(TEMPLATE_KEBAB, names.kebab)


def normalize_template_text(
    rel: str,
    text: str,
    names: ProjectNames,
    *,
    dotted: str | None = None,
    compact: str | None = None,
    ran_cleanup: bool = False,
) -> str:
    """Replay the template-setup transformations onto template-side content.

    After this, a project file that was never edited beyond the standard
    setup steps compares byte-equal to the template file.

    Args:
        rel: Template-relative path of the file.
        text: Raw template-side contents.
        names: Project-side identity tokens.
        dotted: Project Python version as ``MAJOR.MINOR`` (skip when ``None``).
        compact: Project Python version as ``pyMAJORMINOR`` (skip when ``None``).
        ran_cleanup: Whether to drop the template-only pyproject.toml lines.

    Returns:
        The normalized contents.
    """
    text = strip_template_header(normalize_eol(text))
    if dotted is not None and compact is not None:
        text = replay_python_version(rel, text, dotted, compact)
    if rel == "pyproject.toml" and ran_cleanup:
        text = replay_cleanup_pyproject(text)
    text = text.replace(TEMPLATE_SNAKE, names.snake).replace(TEMPLATE_KEBAB, names.kebab)
    if names.github_user is not None:
        text = replace_case_insensitive(text, TEMPLATE_USER, names.github_user)
    return text


def normalize_project_text(text: str) -> str:
    """Normalize project-side content for comparison.

    Args:
        text: Raw project-side contents.

    Returns:
        The contents with line endings normalized and any leftover template
        banner stripped (in case the setup step was skipped).
    """
    return strip_template_header(normalize_eol(text))


def effective_strict(entry: BaselineFile, *, has_mkdocs: bool) -> bool:
    """Compute whether an entry is compared strictly for this project.

    Args:
        entry: The manifest entry.
        has_mkdocs: Whether the project still has mkdocs.

    Returns:
        ``False`` for the files remove_mkdocs.py edits when mkdocs was
        removed; otherwise the entry's own strictness.
    """
    if not has_mkdocs and entry.path in MKDOCS_EDITED:
        return False
    return entry.strict


def script_version_note(template_text: str, project_text: str) -> str:
    """Describe how two helper-script versions relate, for the report line.

    Args:
        template_text: Template-side script source.
        project_text: Project-side script source.

    Returns:
        A parenthesized note, or ``""`` when either version is unavailable.
    """
    template_version = script_version(template_text)
    project_version = script_version(project_text)
    if template_version is None or project_version is None:
        return ""
    template_parts = version_tuple(template_version)
    project_parts = version_tuple(project_version)
    if template_parts is None or project_parts is None:
        return ""
    if project_parts < template_parts:
        return f" (project {project_version} < template {template_version}: outdated)"
    if project_parts > template_parts:
        return f" (project {project_version} > template {template_version}: ahead - upstream?)"
    return f" (both {template_version}: changed without a version bump?)"


def self_check_action(
    template_version: str | None, project_version: str | None, *, same_content: bool
) -> str:
    """Decide what the self-check should do about the project's script copy.

    Args:
        template_version: ``__version__`` of the template's copy, if any.
        project_version: ``__version__`` of the project's copy, if any.
        same_content: Whether the two copies are identical (line endings
            normalized).

    Returns:
        ``"ok"`` (identical), ``"ahead"`` (project copy is newer; do not
        overwrite), ``"update"`` (project copy is older or unversioned), or
        ``"refresh"`` (same version but different content).
    """
    if same_content:
        return "ok"
    template_parts = version_tuple(template_version) if template_version else None
    project_parts = version_tuple(project_version) if project_version else None
    if template_parts is None or project_parts is None:
        return "update"
    if project_parts > template_parts:
        return "ahead"
    if project_parts < template_parts:
        return "update"
    return "refresh"


def decode_text(raw: bytes) -> str | None:
    """Decode file bytes as UTF-8 text.

    Args:
        raw: Raw file contents.

    Returns:
        The decoded text (BOM tolerated), or ``None`` for non-UTF-8 content,
        which is then compared byte-for-byte.
    """
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def pyproject_name(root: Path) -> str | None:
    """Read the ``[project] name`` from a repository's pyproject.toml.

    Args:
        root: Repository root.

    Returns:
        The distribution name, or ``None`` when the file is missing,
        unparsable, or has no name.
    """
    path = root / "pyproject.toml"
    if not path.is_file():
        return None
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError, tomllib.TOMLDecodeError:
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    name = project.get("name")
    return name if isinstance(name, str) else None


def compare_one(entry: BaselineFile, ctx: CompareContext) -> Comparison:
    """Compare one baseline file between the template and the project.

    Args:
        entry: The manifest entry to compare.
        ctx: Comparison context (roots, names, normalization switches).

    Returns:
        The :class:`Comparison` result, carrying the normalized texts when
        the contents differ (for ``--diff``).
    """
    project_rel = map_project_path(entry.path, ctx.names)
    template_path = ctx.template_root / entry.path
    project_path = ctx.project_root / project_rel

    if not template_path.is_file():
        return Comparison(entry, project_rel, "no-template", " (not in this template checkout)")
    if not project_path.is_file():
        return Comparison(entry, project_rel, "missing" if entry.required else "absent")

    template_raw = template_path.read_bytes()
    project_raw = project_path.read_bytes()
    strict = effective_strict(entry, has_mkdocs=ctx.has_mkdocs)

    template_text = decode_text(template_raw)
    project_text = decode_text(project_raw)
    if template_text is None or project_text is None:
        if template_raw == project_raw:
            return Comparison(entry, project_rel, "match")
        return Comparison(entry, project_rel, "modified" if strict else "review", " (binary)")

    template_norm = normalize_template_text(
        entry.path,
        template_text,
        ctx.names,
        dotted=ctx.dotted,
        compact=ctx.compact,
        ran_cleanup=ctx.ran_cleanup,
    )
    project_norm = normalize_project_text(project_text)
    if template_norm == project_norm:
        return Comparison(entry, project_rel, "match")

    note = ""
    if entry.path.startswith("scripts/") and entry.path.endswith(".py"):
        note = script_version_note(template_text, project_text)
    if entry.strict and not strict:
        note += " (compared leniently: mkdocs removed)"
    elif not entry.strict:
        note += " (expected to differ)"
    return Comparison(
        entry,
        project_rel,
        "modified" if strict else "review",
        note,
        template_norm=template_norm,
        project_norm=project_norm,
    )


# ---------------------------------------------------------------------------
# Orchestration (interactive; not unit-tested)
# ---------------------------------------------------------------------------


def same_path(a: str, b: str) -> bool:
    """Compare two filesystem paths without requiring either to exist.

    Args:
        a: First path.
        b: Second path.

    Returns:
        ``True`` if the paths refer to the same location (case-insensitive
        on Windows).
    """
    return normcase(normpath(a)) == normcase(normpath(b))


def parse_args() -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Compare this repository's baseline files against its template."
    )
    parser.add_argument(
        "other_repo",
        nargs="?",
        default=None,
        help="path to the other repository (default: a sibling folder with the template's name)",
    )
    parser.add_argument(
        "--diff", action="store_true", help="show unified diffs for every differing file"
    )
    parser.add_argument(
        "--all", action="store_true", help="list every baseline file, including matches"
    )
    parser.add_argument(
        "--github-user",
        default=None,
        help="project GitHub username for normalization (default: parsed from 'git remote')",
    )
    parser.add_argument(
        "--no-update",
        action="store_true",
        help="report the compare-script versions but never offer to update (for CI)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="assume 'yes' to every confirmation prompt (non-interactive)",
    )
    return parser.parse_args()


def resolve_other_root(argument: str | None, this_root: Path) -> Path:
    """Resolve the other repository's root from the CLI argument or default.

    Args:
        argument: The positional path argument, if given.
        this_root: Root of the repository this script runs from.

    Returns:
        The other repository's root.
    """
    if argument is not None:
        other = Path(argument).resolve()
        if not (other / "pyproject.toml").is_file():
            cli.die(f"'{other}' does not look like a repository (no pyproject.toml).")
        return other
    for name in (TEMPLATE_SNAKE, TEMPLATE_KEBAB):
        candidate = (this_root.parent / name).resolve()
        if candidate != this_root and (candidate / "pyproject.toml").is_file():
            return candidate
    cli.die(
        "No template checkout found in a sibling folder; "
        "pass the other repository's path as an argument."
    )


def orient(this_root: Path, other_root: Path) -> tuple[Path, Path]:
    """Work out which repository is the template and which is the project.

    Args:
        this_root: Root of the repository this script runs from.
        other_root: Root of the repository given on the command line.

    Returns:
        A ``(template_root, project_root)`` pair.
    """
    this_is_template = pyproject_name(this_root) == TEMPLATE_KEBAB
    other_is_template = pyproject_name(other_root) == TEMPLATE_KEBAB
    if this_is_template and other_is_template:
        cli.die("Both repositories are the template; nothing to compare.")
    if not this_is_template and not other_is_template:
        cli.die(
            f"Neither repository's pyproject.toml has [project] name '{TEMPLATE_KEBAB}'; "
            "one side must be a template checkout."
        )
    if this_is_template:
        return this_root, other_root
    return other_root, this_root


def resolve_names(project_root: Path, github_user_override: str | None) -> ProjectNames:
    """Determine the project's identity tokens for normalization.

    Args:
        project_root: Root of the project checkout.
        github_user_override: The ``--github-user`` value, if given.

    Returns:
        The project's names; ``github_user`` is ``None`` when no override was
        given and the origin remote is not a GitHub URL.
    """
    kebab = pyproject_name(project_root)
    if kebab is None:
        cli.die(f"Could not read [project] name from {project_root / 'pyproject.toml'}.")
    snake = kebab.replace("-", "_")
    github_user = github_user_override
    if github_user is None:
        url = cli.capture_ok(["git", "-C", str(project_root), "remote", "get-url", "origin"])
        if url is not None:
            github_user = github_user_from_url(url)
    return ProjectNames(snake=snake, kebab=kebab, github_user=github_user)


def run_self_check(template_root: Path, project_root: Path, *, allow_update: bool) -> None:
    """Compare the two copies of this script and offer to update the project's.

    Runs before the main comparison so an outdated copy (with an outdated
    manifest) is caught first. When the running copy itself is replaced, the
    script exits so the user re-runs the updated version.

    Args:
        template_root: Root of the template checkout.
        project_root: Root of the project checkout.
        allow_update: Whether updating may be offered (``False`` under
            ``--no-update``).
    """
    cli.section("Self-check")
    template_path = template_root / SELF_REL
    project_path = project_root / SELF_REL

    if not template_path.is_file():
        cli.warn(f"  The template has no {SELF_REL}; skipping the self-check.")
        return
    template_text = decode_text(template_path.read_bytes()) or ""
    template_version = script_version(template_text)
    cli.info("Template copy", template_version or "(no __version__)")

    if not project_path.is_file():
        cli.warn(f"  The project has no {SELF_REL}.")
        if allow_update and cli.confirm("  Copy the template's script into the project?"):
            shutil.copyfile(template_path, project_path)
            cli.success(f"  Installed {SELF_REL} into the project.")
        return

    project_text = decode_text(project_path.read_bytes()) or ""
    project_version = script_version(project_text)
    cli.info("Project copy", project_version or "(no __version__)")

    same = normalize_eol(template_text) == normalize_eol(project_text)
    action = self_check_action(template_version, project_version, same_content=same)
    if action == "ok":
        cli.success("  The project's copy matches the template.")
        return
    if action == "ahead":
        cli.warn("  The project's copy is NEWER than the template's.")
        cli.warn("  Consider upstreaming the change to the template; not overwriting it.")
        return

    if action == "update":
        cli.warn("  The project's copy is outdated (so is the file manifest it compares).")
    else:  # "refresh": same version, different content
        cli.warn("  The copies share a version but their contents differ (missing bump?).")
    if not allow_update:
        cli.warn("  Skipping the update offer (--no-update).")
        return
    if not cli.confirm("  Update the project's copy from the template before comparing?"):
        cli.warn("  Continuing with the current copy; it will be flagged in the comparison.")
        return
    shutil.copyfile(template_path, project_path)
    cli.success(f"  Updated {SELF_REL}.")
    if same_path(str(project_path), str(Path(__file__).resolve())):
        print("  The running copy was replaced; re-run the script to compare with it.")
        sys.exit(0)


def build_context(template_root: Path, project_root: Path, names: ProjectNames) -> CompareContext:
    """Assemble the comparison context from the project's on-disk state.

    Args:
        template_root: Root of the template checkout.
        project_root: Root of the project checkout.
        names: Project-side identity tokens.

    Returns:
        The context used by :func:`compare_one`.
    """
    dotted: str | None = None
    compact: str | None = None
    version_file = project_root / ".python-version"
    if version_file.is_file():
        try:
            _full, dotted, compact = python_version_forms(
                version_file.read_text(encoding="utf-8").strip()
            )
        except OSError, ValueError:
            cli.warn("  Could not parse the project's .python-version; not normalizing it.")
    return CompareContext(
        template_root=template_root,
        project_root=project_root,
        names=names,
        dotted=dotted,
        compact=compact,
        ran_cleanup=not (project_root / "scripts" / "template_setup").exists(),
        has_mkdocs=(project_root / "mkdocs.yml").is_file(),
    )


_STATUS_COLORS = {
    "modified": cli.RED,
    "missing": cli.RED,
    "review": cli.YELLOW,
    "no-template": cli.YELLOW,
    "match": cli.GREEN,
    "absent": cli.GRAY,
}


def print_results(results: list[Comparison], *, show_all: bool) -> None:
    """Print the per-file report lines.

    Args:
        results: Comparison results in manifest order.
        show_all: Whether to include matching and absent-optional files.
    """
    shown = [r for r in results if show_all or r.status not in ("match", "absent")]
    if not shown:
        cli.success("  All baseline files match the template.")
        return
    for result in shown:
        color = _STATUS_COLORS.get(result.status, "")
        path_display = result.entry.path
        if result.project_rel != result.entry.path:
            path_display = f"{result.entry.path} -> {result.project_rel}"
        print(
            f"  {color}{result.status:<12}{cli.RESET}{path_display}"
            f"{cli.GRAY}{result.note}{cli.RESET}"
        )


def print_diffs(results: list[Comparison]) -> None:
    """Print a unified diff for every differing text file.

    Diffs compare the normalized texts, so expected renames do not appear.

    Args:
        results: Comparison results in manifest order.
    """
    for result in results:
        if result.status not in ("modified", "review"):
            continue
        cli.section(f"Diff: {result.entry.path}")
        if result.template_norm is None or result.project_norm is None:
            print("  (binary file; no diff)")
            continue
        diff = difflib.unified_diff(
            result.template_norm.splitlines(),
            result.project_norm.splitlines(),
            fromfile=f"template/{result.entry.path}",
            tofile=f"project/{result.project_rel}",
            lineterm="",
        )
        for line in diff:
            if line.startswith(("+++", "---", "@@")):
                print(f"{cli.CYAN}{line}{cli.RESET}")
            elif line.startswith("+"):
                print(f"{cli.GREEN}{line}{cli.RESET}")
            elif line.startswith("-"):
                print(f"{cli.RED}{line}{cli.RESET}")
            else:
                print(line)


def main() -> None:
    """Run the template comparison."""
    args = parse_args()
    cli.set_assume_yes(args.yes)

    print(f"{cli.CYAN}compare_to_template - baseline drift report{cli.RESET}")
    cli.info("Script version", __version__)

    this_root = Path(__file__).resolve().parent.parent
    other_root = resolve_other_root(args.other_repo, this_root)
    template_root, project_root = orient(this_root, other_root)
    names = resolve_names(project_root, args.github_user)

    cli.section("Repositories")
    cli.info("Template", str(template_root))
    cli.info("Project", str(project_root))
    cli.info("Project names", f"{names.snake} / {names.kebab}")
    if names.github_user is None:
        cli.warn("  No GitHub username found (origin remote is not GitHub?).")
        cli.warn("  Username differences will show as drift; pass --github-user to fix.")
    else:
        cli.info("GitHub user", names.github_user)

    run_self_check(template_root, project_root, allow_update=not args.no_update)

    ctx = build_context(template_root, project_root, names)
    results = [compare_one(entry, ctx) for entry in MANIFEST]

    cli.section("Comparison")
    print_results(results, show_all=args.all)
    if args.diff:
        print_diffs(results)

    counts = {status: sum(1 for r in results if r.status == status) for status in _STATUS_COLORS}
    cli.section("Summary")
    cli.info("Baseline files", str(len(results)))
    cli.info("Match", str(counts["match"]))
    cli.info("Modified (drift)", str(counts["modified"]))
    cli.info("Missing (drift)", str(counts["missing"]))
    cli.info("Review only", str(counts["review"]))
    cli.info("Absent (optional)", str(counts["absent"]))
    if counts["no-template"]:
        cli.info("Not in template", str(counts["no-template"]))

    differing = counts["modified"] + counts["review"]
    if differing and not args.diff:
        print(f"\n  {cli.GRAY}Run again with --diff to see the differences.{cli.RESET}")

    drift = counts["modified"] + counts["missing"]
    print()
    if drift:
        cli.warn(f"Drift detected in {drift} baseline file(s).")
        sys.exit(1)
    cli.success("No drift in strict baseline files.")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):  # fmt: skip
        print()
        sys.exit(130)
