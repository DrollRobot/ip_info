"""Open the project and global Claude Code settings files in an editor.

Walks up from a starting directory (the current directory by default) to find the
nearest ``.claude`` folder, then opens the project settings it contains:

    <nearest>/.claude/settings.json          -- shared, checked-in settings
    <nearest>/.claude/settings.local.json    -- personal, git-ignored settings

It also opens the global settings file when present:

    ~/.claude/settings.json                  -- user-wide settings

By default only files that already exist are opened. Pass ``--create`` to create
any that are missing (as an empty ``{}`` JSON object) before opening them.

Usage:
    uv run scripts/open_claude_settings.py
    uv run scripts/open_claude_settings.py --create
    uv run scripts/open_claude_settings.py --path ../other-project
    uv run scripts/open_claude_settings.py --editor "code -r"
    uv run scripts/open_claude_settings.py --dry-run

Editor selection (first that applies wins):
    --editor  ->  $VISUAL  ->  $EDITOR  ->  ``code`` on PATH  ->  OS default opener
"""

from __future__ import annotations

import argparse
import os
import platform
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

import _cli as cli

# Version of this helper script itself. Bump on every change so copies in other
# repos can be compared: patch = bugfix, minor = new flag/behavior, major =
# breaking CLI change.
__version__ = "1.0.1"

# Written into any settings file created with --create: a valid, empty JSON
# object that Claude Code accepts as-is.
_EMPTY_SETTINGS = "{}\n"

# Names of the project-level settings files inside a .claude folder, in the
# order they should be opened.
_PROJECT_FILES = ("settings.json", "settings.local.json")


def find_local_claude_dir(start: Path) -> Path | None:
    """Return the nearest ``.claude`` directory at or above *start*.

    Walks *start* and each of its parents up to the filesystem root, returning
    the first existing ``.claude`` directory found.

    Args:
        start: Directory to begin the upward search from.

    Returns:
        The nearest ``.claude`` directory, or ``None`` if none exists on the
        path from *start* to the root.
    """
    for directory in (start, *start.parents):
        candidate = directory / ".claude"
        if candidate.is_dir():
            return candidate
    return None


def global_settings_file() -> Path:
    """Return the path to the user-wide global settings file (~/.claude/settings.json)."""
    return Path.home() / ".claude" / "settings.json"


def collect_targets(start: Path, *, create: bool) -> list[Path]:
    """Work out which settings files to open, in order and de-duplicated.

    The project files come from the nearest ``.claude`` folder at or above
    *start*. When *create* is set and no such folder exists, one is located in
    *start* itself so the files can be created there.

    Args:
        start: Directory to begin the upward search for ``.claude`` from.
        create: Whether missing files will be created (affects which project
            ``.claude`` folder is chosen when none already exists).

    Returns:
        Ordered list of settings file paths (project files first, then the
        global file), with duplicates removed by resolved path.
    """
    targets: list[Path] = []

    local_dir = find_local_claude_dir(start)
    if local_dir is None and create:
        # No project .claude anywhere above us; create one here so --create has
        # somewhere to put the new files.
        local_dir = start / ".claude"

    if local_dir is None:
        cli.warn(f"No .claude folder found at or above {start} (use --create to make one).")
    else:
        cli.info("Project .claude", str(local_dir))
        targets.extend(local_dir / name for name in _PROJECT_FILES)

    targets.append(global_settings_file())
    cli.info("Global settings", str(global_settings_file()))

    # De-duplicate by resolved path while preserving order: the nearest .claude
    # can itself be ~/.claude, which would otherwise list the global file twice.
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in targets:
        key = path.expanduser().resolve()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def ensure_files(paths: Sequence[Path]) -> None:
    """Create any missing settings files (and their ``.claude`` parents).

    Existing files are left untouched. New files are written with an empty
    ``{}`` JSON object.

    Args:
        paths: Settings files to create if absent.
    """
    for path in paths:
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_EMPTY_SETTINGS, encoding="utf-8")
        cli.success(f"Created {path}")


def resolve_opener(explicit: str | None) -> tuple[str, list[str]] | None:
    """Choose the editor command used to open the settings files.

    Selection order: an explicit ``--editor`` value, then ``$VISUAL``, then
    ``$EDITOR``, then ``code`` if it is on ``PATH``. Returns ``None`` when none
    of these are available, signalling the caller to fall back to the OS default
    file opener.

    Args:
        explicit: Value of the ``--editor`` flag, or ``None`` if not given.

    Returns:
        A ``(label, argv_prefix)`` pair whose ``argv_prefix`` is the editor
        command split into arguments, or ``None`` for the OS-default fallback.
    """
    for source, value in (
        ("--editor", explicit),
        ("$VISUAL", os.environ.get("VISUAL")),
        ("$EDITOR", os.environ.get("EDITOR")),
    ):
        if value and value.strip():
            return source, shlex.split(value, posix=(os.name != "nt"))

    from shutil import which

    if which("code"):
        return "code", ["code"]

    return None


def launch_argv(argv: list[str]) -> list[str]:
    """Adapt an editor command line so it launches on the current platform.

    On Windows, common editor entry points are batch files (VS Code's ``code``
    is ``code.cmd``), which ``CreateProcess`` — and therefore ``subprocess``
    without a shell — cannot run directly. Such commands are routed through
    ``cmd /c``. On other platforms, and for real executables, the command is
    returned unchanged.

    Args:
        argv: The command and its arguments, editor first.

    Returns:
        A command line suitable for :func:`subprocess.run` on this platform.
    """
    # platform.system() (unlike os.name/sys.platform) is not constant-folded by
    # type checkers, so this Windows branch stays analyzable on every platform.
    if platform.system() == "Windows" and argv:
        from shutil import which

        resolved = which(argv[0])
        if resolved and Path(resolved).suffix.lower() in (".cmd", ".bat"):
            return ["cmd", "/c", resolved, *argv[1:]]
    return argv


def open_with_os_default(path: Path) -> None:
    """Open a single file with the operating system's default handler.

    Args:
        path: File to open.
    """
    if sys.platform == "win32":
        os.startfile(str(path))  # noqa: S606  (Windows-only; guarded by sys.platform)
        return
    opener = "open" if sys.platform == "darwin" else "xdg-open"
    cli.run([opener, str(path)])


def open_files(paths: Sequence[Path], opener: tuple[str, list[str]] | None) -> None:
    """Open the given files with the resolved editor, or the OS default opener.

    Editor commands receive every file in a single invocation (so terminal
    editors open them as buffers/tabs); the OS-default fallback opens each file
    on its own since those launchers take one path at a time.

    Args:
        paths: Files to open.
        opener: Result of :func:`resolve_opener`; ``None`` uses the OS default.
    """
    if not paths:
        cli.warn("Nothing to open.")
        return

    if opener is None:
        for path in paths:
            open_with_os_default(path)
        return

    label, argv_prefix = opener
    cli.info("Opening with", label)
    cli.run([*argv_prefix, *(str(p) for p in paths)])


def main() -> None:
    """Parse CLI arguments and open the project and global Claude settings files."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path.cwd(),
        metavar="DIR",
        help="Directory to start the upward search for .claude from (default: current directory).",
    )
    parser.add_argument(
        "-c",
        "--create",
        action="store_true",
        help="Create any missing settings files (as an empty '{}') before opening them.",
    )
    parser.add_argument(
        "--editor",
        default=None,
        metavar="CMD",
        help="Editor command to open files with, e.g. 'code -r' (overrides $VISUAL/$EDITOR).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List the settings files that would be opened, without creating or opening them.",
    )
    args = parser.parse_args()

    cli.section("Open Claude settings")
    cli.info("Script version", __version__)

    start = args.path.expanduser()
    if not start.is_dir():
        cli.die(f"--path is not a directory: {start}")
    start = start.resolve()

    targets = collect_targets(start, create=args.create)

    if args.dry_run:
        cli.section("Would open")
        # With --create, missing files would be created first, so they would be
        # opened too; without it, only files that already exist are opened.
        would_open = targets if args.create else [p for p in targets if p.exists()]
        if not would_open:
            cli.warn("No settings files to open (pass --create to make them).")
        for path in would_open:
            note = "" if path.exists() else "  (would be created)"
            print(f"  {path}{note}")
        return

    if args.create:
        ensure_files(targets)

    existing = [path for path in targets if path.exists()]
    for path in targets:
        if not path.exists():
            cli.warn(f"Skipping (does not exist): {path}")

    cli.section("Opening")
    open_files(existing, resolve_opener(args.editor))
    if existing:
        cli.success(f"Opened {len(existing)} file(s).")


if __name__ == "__main__":
    main()
