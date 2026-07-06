"""Open the local and global gitignore files in an editor.

For the git repository containing a starting directory (the current directory by
default), opens the three kinds of ignore file that apply to it:

    <repo>/.gitignore            -- committed, shared with everyone who clones
    <repo>/.git/info/exclude     -- local to this clone, never committed
    <global excludes>            -- user-wide (git's core.excludesfile, or the
                                    default ~/.config/git/ignore)

By default only files that already exist are opened. Pass ``--create`` to create
any that are missing (with a one-line header comment) before opening them.

If *start* is not inside a git repository, only the global excludes file applies;
the two repository-level files are skipped.

Usage:
    uv run scripts/open_gitignore.py
    uv run scripts/open_gitignore.py --create
    uv run scripts/open_gitignore.py --path ../other-project
    uv run scripts/open_gitignore.py --editor "code -r"
    uv run scripts/open_gitignore.py --dry-run

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
from dataclasses import dataclass
from pathlib import Path

import _cli as cli

# Version of this helper script itself. Bump on every change so copies in other
# repos can be compared: patch = bugfix, minor = new flag/behavior, major =
# breaking CLI change.
__version__ = "1.0.0"

# Header comments written into each file created with --create. Unlike JSON,
# gitignore files allow comments, so a freshly-created file names itself instead
# of opening blank. Each is valid as-is (an all-comment ignore file matches
# nothing).
_COMMITTED_HEADER = (
    "# Committed .gitignore -- patterns shared with everyone who clones this repo.\n"
)
_LOCAL_HEADER = (
    "# Local git excludes (.git/info/exclude) -- patterns for this clone only,\n"
    "# never committed.\n"
)
_GLOBAL_HEADER = "# Global git excludes -- patterns ignored across all of your repositories.\n"


@dataclass(frozen=True)
class Target:
    """A gitignore file to open, with the header used when creating it.

    Attributes:
        label: Human-readable name for logs (e.g. ``"committed .gitignore"``).
        path: Absolute path to the ignore file (may not exist yet).
        header: Comment header written to the file if ``--create`` makes it.
    """

    label: str
    path: Path
    header: str


def repo_root(start: Path) -> Path | None:
    """Return the work-tree root of the git repository containing *start*.

    Args:
        start: Directory to resolve the repository from.

    Returns:
        The absolute repository root, or ``None`` if *start* is not inside a
        git work tree.
    """
    top = cli.capture_ok(["git", "-C", str(start), "rev-parse", "--show-toplevel"])
    return Path(top) if top else None


def local_exclude_file(start: Path) -> Path | None:
    """Return the path to this clone's ``.git/info/exclude`` file.

    Uses ``git rev-parse --git-path`` so the location is correct for linked
    worktrees and non-default ``$GIT_DIR`` layouts, where the exclude file lives
    in the shared common directory rather than a literal ``.git/info``.

    Args:
        start: Directory inside the repository.

    Returns:
        The absolute path to the exclude file (which need not exist yet), or
        ``None`` if *start* is not inside a git repository.
    """
    raw = cli.capture_ok(["git", "-C", str(start), "rev-parse", "--git-path", "info/exclude"])
    if raw is None:
        return None
    # --git-path returns a path relative to *start* (because of ``-C``), or an
    # absolute one; ``start / raw`` handles both (an absolute right-hand side
    # discards the left).
    return (start / raw).resolve()


def global_excludes_file() -> Path:
    """Return the path to the user-wide global excludes file.

    Honours ``core.excludesfile`` when it is configured; otherwise falls back to
    git's built-in default of ``$XDG_CONFIG_HOME/git/ignore`` (with
    ``XDG_CONFIG_HOME`` defaulting to ``~/.config``), which git reads
    automatically without any configuration.

    Returns:
        The absolute path to the global excludes file (which need not exist yet).
    """
    configured = cli.capture_ok(["git", "config", "--get", "core.excludesfile"])
    if configured:
        return Path(configured).expanduser().resolve()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return (base / "git" / "ignore").resolve()


def collect_targets(start: Path) -> list[Target]:
    """Work out which gitignore files to open, in order and de-duplicated.

    The repository-level files (committed ``.gitignore`` and local
    ``.git/info/exclude``) are included only when *start* is inside a git work
    tree. The global excludes file is always included.

    Args:
        start: Directory to resolve the repository and files from.

    Returns:
        Ordered list of targets (committed, local, then global), with duplicates
        removed by resolved path.
    """
    targets: list[Target] = []

    root = repo_root(start)
    if root is None:
        cli.warn(f"Not inside a git repository at or above {start}.")
        cli.warn("Only the global excludes file will be opened.")
    else:
        cli.info("Repository root", str(root))
        targets.append(Target("committed .gitignore", root / ".gitignore", _COMMITTED_HEADER))
        exclude = local_exclude_file(start)
        if exclude is not None:
            cli.info("Local exclude", str(exclude))
            targets.append(Target("local exclude", exclude, _LOCAL_HEADER))

    global_file = global_excludes_file()
    cli.info("Global excludes", str(global_file))
    targets.append(Target("global excludes", global_file, _GLOBAL_HEADER))

    # De-duplicate by resolved path while preserving order, in case the global
    # excludes file happens to sit inside the repository.
    seen: set[Path] = set()
    unique: list[Target] = []
    for target in targets:
        key = target.path.expanduser().resolve()
        if key not in seen:
            seen.add(key)
            unique.append(target)
    return unique


def ensure_files(targets: Sequence[Target]) -> None:
    """Create any missing ignore files (and their parent directories).

    Existing files are left untouched. New files are written with the target's
    one-line header comment.

    Args:
        targets: Ignore files to create if absent.
    """
    for target in targets:
        if target.path.exists():
            continue
        target.path.parent.mkdir(parents=True, exist_ok=True)
        target.path.write_text(target.header, encoding="utf-8")
        cli.success(f"Created {target.path}")


def resolve_opener(explicit: str | None) -> tuple[str, list[str]] | None:
    """Choose the editor command used to open the ignore files.

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
    is ``code.cmd``), which ``CreateProcess`` -- and therefore ``subprocess``
    without a shell -- cannot run directly. Such commands are routed through
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
    cli.run(launch_argv([*argv_prefix, *(str(p) for p in paths)]))


def main() -> None:
    """Parse CLI arguments and open the local and global gitignore files."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path.cwd(),
        metavar="DIR",
        help="Directory to resolve the git repository from (default: current directory).",
    )
    parser.add_argument(
        "-c",
        "--create",
        action="store_true",
        help="Create any missing ignore files (with a header comment) before opening them.",
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
        help="List the ignore files that would be opened, without creating or opening them.",
    )
    args = parser.parse_args()

    cli.section("Open gitignore files")
    cli.info("Script version", __version__)

    start = args.path.expanduser()
    if not start.is_dir():
        cli.die(f"--path is not a directory: {start}")
    start = start.resolve()

    targets = collect_targets(start)

    if args.dry_run:
        cli.section("Would open")
        # With --create, missing files would be created first, so they would be
        # opened too; without it, only files that already exist are opened.
        would_open = targets if args.create else [t for t in targets if t.path.exists()]
        if not would_open:
            cli.warn("No ignore files to open (pass --create to make them).")
        for target in would_open:
            note = "" if target.path.exists() else "  (would be created)"
            print(f"  {target.path}{note}")
        return

    if args.create:
        ensure_files(targets)

    existing = [target for target in targets if target.path.exists()]
    for target in targets:
        if not target.path.exists():
            cli.warn(f"Skipping (does not exist): {target.path}")

    cli.section("Opening")
    open_files([target.path for target in existing], resolve_opener(args.editor))
    if existing:
        cli.success(f"Opened {len(existing)} file(s).")


if __name__ == "__main__":
    main()
