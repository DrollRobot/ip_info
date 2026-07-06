"""Interactively delete a finished git worktree created by new_worktree.py.

The inverse of new_worktree.py, and the final step of the worktree lifecycle:

    new_worktree  ->  (work, commit, complete_worktree)  ->  remove_worktree

Run this once the work is done: the PR opened from the worktree's 'wt/<slug>'
branch has been merged into develop and the worktree is no longer needed.

WARNING: this permanently deletes the worktree directory and its local
branch. It walks through the teardown one step at a time, showing what is
about to happen and prompting for confirmation (y/n) before each action;
answering 'n' stops without taking the remaining steps. The output of every
git command is shown.

Steps:
  1. Refresh develop  - git switch develop (if needed) + git pull --ff-only origin develop
  2. Remove worktree  - git worktree remove --force <path>
  3. Delete branch    - git branch -D wt/<slug>
  4. Prune stale refs - git fetch --prune

Before each destructive step it warns about work that the force flags would
otherwise discard silently: uncommitted changes in the worktree (step 2) and
commits on the branch that were never pushed to origin (step 3). Each warning
is its own y/n confirmation, so nothing is lost without an explicit yes.

Paths and names are derived exactly as new_worktree.py derives them, so the
same slug that created a worktree will clean it up. Every step runs against
the main worktree, so this is safe to run even from inside the worktree
being removed (git refuses to remove the worktree you are standing in).

Run without a slug to pick one interactively: the script lists every open
worktree whose branch carries the wt/ prefix and asks which to remove.

Pass -y/--yes to answer every prompt with 'y' for non-interactive use (a slug
is required in that case, since there is nobody to answer the picker).

Usage:
    python scripts/remove_worktree.py issue-42
    python scripts/remove_worktree.py fix/login
    python scripts/remove_worktree.py issue-42 -y
    python scripts/remove_worktree.py

Paths and names mirror new_worktree.py: the sibling '<repo>-wt' folder and
'wt/<slug>' branches.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

import _cli as cli

# Version of this helper script itself. Bump on every change so copies in other
# repos can be compared: patch = bugfix, minor = new flag/behavior, major =
# breaking CLI change.
__version__ = "1.2.3"


def slug_arg(value: str) -> str:
    """Validate the worktree slug (same rules as new_worktree.py).

    Args:
        value: Slug from the command line.

    Returns:
        The validated slug.

    Raises:
        argparse.ArgumentTypeError: If the slug contains disallowed characters.
    """
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", value):
        raise argparse.ArgumentTypeError(
            "slug may only contain letters, digits, and . _ / - characters"
        )
    if ".." in value:
        raise argparse.ArgumentTypeError("slug may not contain '..'")
    if value.startswith("/") or value.endswith("/"):
        raise argparse.ArgumentTypeError("slug may not start or end with '/'")
    if "//" in value:
        raise argparse.ArgumentTypeError("slug may not contain '//'")
    return value


def parse_args() -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Delete a finished git worktree created by new_worktree.py."
    )
    parser.add_argument(
        "slug",
        type=slug_arg,
        nargs="?",
        default=None,
        help="the same slug passed to new_worktree.py (omit to pick from a list of open worktrees)",
    )
    parser.add_argument(
        "base",
        nargs="?",
        default="develop",
        help="integration branch to refresh, that the PR was merged into (default: develop)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="assume 'yes' to every confirmation prompt (non-interactive)",
    )
    args = parser.parse_args()
    if args.yes and args.slug is None:
        parser.error("a slug is required with -y/--yes (there is nobody to answer the picker)")
    return args


def same_path(a: str, b: str) -> bool:
    """Compare two filesystem paths without requiring either to exist.

    Normalises slash direction and trailing separators; case-insensitive on
    Windows (via ``os.path.normcase``).

    Args:
        a: First path.
        b: Second path.

    Returns:
        ``True`` if the paths refer to the same location.
    """
    return os.path.normcase(os.path.normpath(a)) == os.path.normcase(os.path.normpath(b))


def parse_worktrees(porcelain: str) -> list[tuple[str, str | None]]:
    """Parse ``git worktree list --porcelain`` output into (path, branch) pairs.

    Args:
        porcelain: Raw porcelain output.

    Returns:
        One ``(path, branch_ref)`` pair per worktree, in listing order (the
        main worktree first). ``branch_ref`` is the full ref (e.g.
        ``refs/heads/wt/issue-42``), or ``None`` for a detached HEAD.
    """
    entries: list[tuple[str, str | None]] = []
    path: str | None = None
    branch: str | None = None
    for line in porcelain.splitlines():
        if line.startswith("worktree "):
            if path is not None:
                entries.append((path, branch))
            path = line.removeprefix("worktree ")
            branch = None
        elif line.startswith("branch "):
            branch = line.removeprefix("branch ")
    if path is not None:
        entries.append((path, branch))
    return entries


def open_worktree_slugs(
    worktrees: Sequence[tuple[str, str | None]], prefix: str
) -> list[tuple[str, str]]:
    """Find the open worktrees that look like they were made by new_worktree.py.

    Args:
        worktrees: ``(path, branch_ref)`` pairs from :func:`parse_worktrees`.
        prefix: Branch prefix (e.g. ``wt/``).

    Returns:
        ``(slug, path)`` pairs for every linked worktree (the main worktree is
        skipped) whose branch starts with the prefix.
    """
    ref_prefix = f"refs/heads/{prefix}"
    return [
        (branch.removeprefix(ref_prefix), path)
        for path, branch in worktrees[1:]
        if branch is not None and branch.startswith(ref_prefix)
    ]


def parse_choice(answer: str, count: int) -> int | None:
    """Parse a 1-based menu selection.

    Args:
        answer: Raw user input.
        count: Number of menu entries.

    Returns:
        The selected number, or ``None`` if the input is not a number in
        ``1..count``.
    """
    try:
        value = int(answer)
    except ValueError:
        return None
    if not 1 <= value <= count:
        return None
    return value


def prompt_for_slug(candidates: list[tuple[str, str]]) -> str:
    """Show the open worktrees and ask which one to remove.

    Args:
        candidates: ``(slug, path)`` pairs from :func:`open_worktree_slugs`.

    Returns:
        The slug of the selected worktree.
    """
    cli.section("Open worktrees")
    for index, (slug, path) in enumerate(candidates, start=1):
        print(f"  {index}. {slug}  {cli.GRAY}{path}{cli.RESET}")
    print()
    while True:
        answer = input(f"Which worktree should be removed? [1-{len(candidates)}] ").strip()
        choice = parse_choice(answer, len(candidates))
        if choice is not None:
            return candidates[choice - 1][0]
        print(f"  Please enter a number between 1 and {len(candidates)}.")


def main() -> None:
    """Run the interactive worktree teardown flow."""
    args = parse_args()
    cli.set_assume_yes(args.yes)

    cli.info("Script version", __version__)
    print("")

    # --- what this does (shown up front, before anything is touched) ------------

    intro = (
        "  The inverse of new_worktree.py. Run it once the work is done: the PR",
        "  opened from this worktree's wt/<slug> branch has been merged into",
        "  develop, and the worktree is no longer needed.",
    )
    print()
    print(f"{cli.CYAN}remove_worktree - tear down a finished worktree{cli.RESET}")
    print()
    for line in intro:
        print(f"{cli.GRAY}{line}{cli.RESET}")
    print()
    cli.warn("  WARNING: this DELETES the worktree directory and its local branch.")
    cli.warn("  It runs one step at a time and asks before each; answer n to stop.")

    # --- resolve paths (mirrors new_worktree.py) -------------------------------

    # Resolve the MAIN worktree, not whichever worktree we happen to be standing
    # in: `git worktree list` always reports the main worktree first. Deriving
    # names from it means this works even when run from inside the worktree we
    # remove.
    porcelain = cli.capture(["git", "worktree", "list", "--porcelain"])
    worktrees = parse_worktrees(porcelain)
    worktree_paths = [path for path, _ in worktrees]
    if not worktree_paths:
        cli.die("Could not determine the main worktree (are you inside a git repository?).")
    main_repo = worktree_paths[0]

    repo_name = Path(main_repo).name
    prefix = "wt/"

    slug = args.slug
    if slug is None:
        candidates = open_worktree_slugs(worktrees, prefix)
        if not candidates:
            cli.die(
                f"No open worktrees with branch prefix '{prefix}' found. "
                "Pass a slug to clean up leftovers (e.g. a branch without a worktree)."
            )
        slug = prompt_for_slug(candidates)

    cli.section("Cleanup setup")

    branch = f"{prefix}{slug}"
    dir_slug = slug.replace("/", "-")
    wt_home = Path(main_repo).parent / f"{repo_name}-wt"
    wt_path = wt_home / dir_slug

    cli.info("Slug", slug)
    cli.info("Branch", branch)
    cli.info("Worktree", str(wt_path))
    cli.info("Integration branch", args.base)
    cli.info("Main worktree", main_repo)

    # --- preflight: figure out what actually still exists -----------------------

    wt_registered = any(same_path(p, str(wt_path)) for p in worktree_paths)
    if not wt_registered:
        cli.warn(f"  Note: no registered worktree at '{wt_path}' - remove step will be skipped.")

    branch_exists = bool(cli.capture(["git", "branch", "--list", branch]))
    if not branch_exists:
        cli.warn(f"  Note: branch '{branch}' does not exist - delete-branch step will be skipped.")

    if not wt_registered and not branch_exists:
        print()
        cli.success(f"Nothing to clean up for slug '{slug}'.")
        sys.exit(0)

    # Operate from the main worktree for every step. This guarantees the
    # worktree being removed is never the "current" one (git refuses to remove
    # that) and moves us out of it if we happened to be inside it.
    cli.echo(f"cd {main_repo}")
    os.chdir(main_repo)

    # --- step 1: refresh the integration branch ---------------------------------

    cli.section(f"Step: refresh '{args.base}'")
    current = cli.capture(["git", "branch", "--show-current"])
    current_label = current or "(detached HEAD)"
    cli.info("Current branch", current_label)
    if current != args.base:
        cli.step(f"Switch from '{current_label}' to '{args.base}'?")
        cli.run(["git", "switch", args.base])
    cli.step(f"Pull '{args.base}' from origin (fast-forward only)?")
    cli.run(["git", "pull", "--ff-only", "origin", args.base])

    # --- step 2: remove the worktree --------------------------------------------

    if wt_registered:
        cli.section("Step: remove worktree")
        # --force discards untracked/ignored files (generated .code-workspace,
        # .vscode and .env links, .venv) AND any uncommitted tracked changes.
        # The latter is real work, so surface it before deleting. Tracked-file
        # changes only; the generated/ignored noise above is expected.
        dirty = cli.capture_ok(
            ["git", "-C", str(wt_path), "status", "--porcelain", "--untracked-files=no"]
        )
        if dirty:
            cli.warn("  This worktree has uncommitted changes that --force will discard:")
            for line in dirty.splitlines():
                print(f"  {cli.GRAY}{line}{cli.RESET}")
            if not cli.confirm("  Discard these uncommitted changes and remove the worktree?"):
                cli.die("Aborted: commit, push, or stash the changes first.")
        cli.step(f"DELETE the worktree directory at '{wt_path}'?")
        cli.run(["git", "worktree", "remove", "--force", str(wt_path)])

    # --- step 3: delete the branch ----------------------------------------------

    if branch_exists:
        cli.section("Step: delete branch")
        # -D (force): a squash- or rebase-merged PR leaves the local branch
        # looking unmerged to git, so -d would refuse to delete it. That same
        # force, though, will discard a branch whose commits never reached
        # origin, so warn about unpushed work before deleting.
        remote_ref = f"refs/remotes/origin/{branch}"
        if cli.capture_ok(["git", "rev-parse", "--verify", "--quiet", remote_ref]):
            rng = f"origin/{branch}..{branch}"
            unpushed = int(cli.capture(["git", "rev-list", "--count", rng]))
            if unpushed > 0:
                cli.warn(
                    f"  '{branch}' has {unpushed} commit(s) not pushed to origin/{branch}; "
                    "force-deleting will lose them."
                )
                if not cli.confirm("  Force-delete anyway?"):
                    cli.die("Aborted: push the branch first (e.g. via complete_worktree.py).")
        else:
            ahead = cli.capture_ok(["git", "rev-list", "--count", f"origin/{args.base}..{branch}"])
            detail = f" ({ahead} commit(s) ahead of origin/{args.base})" if ahead else ""
            cli.warn(f"  '{branch}' was never pushed to origin{detail}.")
            cli.warn("  If this work was not merged via a PR, force-deleting will lose it.")
            if not cli.confirm("  Force-delete anyway?"):
                cli.die("Aborted: push or merge the branch first.")
        cli.step(f"Force-delete local branch '{branch}'?")
        cli.run(["git", "branch", "-D", branch])

    # --- step 4: prune stale remote-tracking refs -------------------------------

    cli.section("Step: prune")
    cli.step("Fetch and prune deleted remote branches?")
    cli.run(["git", "fetch", "--prune"])

    # --- done -------------------------------------------------------------------

    cli.section("Done")
    cli.success(f"  Removed worktree '{slug}'.")
    cli.info("Current branch", cli.capture(["git", "branch", "--show-current"]))
    cli.info("Location", os.getcwd())


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):  # fmt: skip
        print()
        sys.exit(130)
