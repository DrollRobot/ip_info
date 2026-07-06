"""Interactively merge the current branch into main, bump the version, tag, and push.

Walks through the release process one step at a time. Before each action it
shows what is about to happen and prompts for confirmation (y/n); answering
'n' aborts without making any further changes. The output of every git and
uv command is shown so the process can be watched as it happens. Pass
-y/--yes to answer every prompt with 'y' for non-interactive use.

Along the way it reports the original branch, the working-tree status, and
the current and target project versions.

The new version can either be bumped semantically (patch/minor/major), set
to an explicit version number with --version, or left unchanged with
--no-version. When --version names the version already in use, the version
change is skipped automatically (same as --no-version). When the version is
not changed (assuming the version was already updated by hand), the version update and
the release commit are skipped.

Usage:
    python scripts/push_new_tag_to_main.py patch
    python scripts/push_new_tag_to_main.py --version 2.0.0
    python scripts/push_new_tag_to_main.py --no-version
    python scripts/push_new_tag_to_main.py patch -y

Bump levels:
    patch — bug fixes only           (1.4.2 -> 1.4.3)
    minor — new features, no breaks  (1.4.2 -> 1.5.0)
    major — breaking changes         (1.4.2 -> 2.0.0)

Before merging it fetches from origin and fast-forwards both the source branch
and main if either is behind its remote, so a release can never be cut from a
stale branch (e.g. a PR merged on the remote but not yet pulled). A diverged
branch aborts.

Requirements:
    - Run from inside the source branch.
    - `uv` installed and the project uses uv for version management.
    - Push access to origin for both main and the source branch.
"""

from __future__ import annotations

import argparse
import re
import sys
import time

import _cli as cli

# Version of this helper script itself (independent of the project version it
# releases). Bump on every change so copies in other repos can be compared:
# patch = bugfix, minor = new flag/behavior, major = breaking CLI change.
__version__ = "1.1.1"


def parse_args() -> argparse.Namespace:
    """Parse and validate the command line.

    Returns:
        The parsed arguments; exactly one of ``bump`` or ``version`` is set.
    """
    parser = argparse.ArgumentParser(
        description="Merge the current branch into main, bump the version, tag, and push."
    )
    parser.add_argument(
        "bump",
        nargs="?",
        choices=("patch", "minor", "major"),
        help="semantic version bump level",
    )
    parser.add_argument(
        "--version",
        help="explicit version number to set (e.g. 1.5.0), instead of a bump",
    )
    parser.add_argument(
        "--no-version",
        action="store_true",
        help="merge and push without changing the version (no release commit or tag)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="assume 'yes' to every confirmation prompt (non-interactive)",
    )
    args = parser.parse_args()

    if sum((bool(args.bump), bool(args.version), args.no_version)) != 1:
        parser.error(
            "specify exactly one of: a bump level (patch/minor/major), --version, or --no-version"
        )
    if args.version and not re.match(r"^\d+\.\d+\.\d+", args.version):
        parser.error(f"--version must look like X.Y.Z, got '{args.version}'")
    return args


def sync_status(local: str, remote: str) -> tuple[int, int] | None:
    """Report how far a local ref is ahead of and behind a remote ref.

    Prints an aligned ``ahead/behind`` summary. Aborts the script if the two
    refs have diverged (each has commits the other lacks), since reconciling
    that is a manual decision the release flow should not make automatically.

    Args:
        local: Local ref name (e.g. ``main`` or the source branch).
        remote: Remote-tracking ref name (e.g. ``origin/main``).

    Returns:
        ``(ahead, behind)`` commit counts, or ``None`` if either ref does not
        exist (nothing to compare).
    """
    if cli.capture_ok(["git", "rev-parse", "--verify", "--quiet", local]) is None:
        return None
    if cli.capture_ok(["git", "rev-parse", "--verify", "--quiet", remote]) is None:
        return None
    ahead = int(cli.capture(["git", "rev-list", "--count", f"{remote}..{local}"]))
    behind = int(cli.capture(["git", "rev-list", "--count", f"{local}..{remote}"]))
    cli.info(f"'{local}' vs {remote}", f"{ahead} ahead, {behind} behind")
    if ahead > 0 and behind > 0:
        cli.die(
            f"Local '{local}' has diverged from {remote} "
            f"({ahead} ahead, {behind} behind); reconcile manually before releasing."
        )
    return ahead, behind


def main() -> None:
    """Run the interactive release flow."""
    args = parse_args()
    cli.set_assume_yes(args.yes)
    use_bump = bool(args.bump)

    cli.info("Script version", __version__)
    print("")

    # --- gather state --------------------------------------------------------

    cli.section("Release setup")

    source = cli.capture_ok(["git", "symbolic-ref", "--short", "HEAD"])
    if not source:
        cli.die("Not on a branch (detached HEAD?)")
    if source == "main":
        cli.die("Already on main; switch to the source branch first.")

    cli.info("Original branch", source)
    cli.info("Target branch", "main")
    if args.no_version:
        cli.info("Version change", "none (--no-version)")
    elif use_bump:
        cli.info("Version change", f"bump '{args.bump}'")
    else:
        cli.info("Version change", f"set to '{args.version}'")

    # --- working tree status -------------------------------------------------

    cli.section("Working tree status")
    cli.run(["git", "status", "--short", "--branch"])

    if cli.exit_code(["git", "diff-index", "--quiet", "HEAD", "--"]) != 0:
        cli.die("Working tree is not clean; commit or stash changes first.")
    cli.success("  Working tree is clean.")

    # --- sync with origin ----------------------------------------------------

    # Guard against releasing a stale branch. If a PR was merged into the
    # source branch on the remote but never pulled, the local branch is behind
    # origin and merging it into main would silently omit those commits. Fetch
    # and fast-forward before anything is merged.
    cli.section("Sync with origin")
    cli.run(["git", "fetch", "origin"])

    # Source branch: it is checked out, so fast-forward it with a pull.
    upstream = f"origin/{source}"
    status = sync_status(source, upstream)
    if status is None:
        cli.info("Note", f"no '{upstream}' on origin; nothing to sync")
    elif status[1] > 0:
        cli.warn(f"  Local '{source}' is {status[1]} commit(s) behind {upstream}.")
        cli.step(f"Fast-forward '{source}' to {upstream}?")
        cli.run(["git", "pull", "--ff-only", "origin", source])
    else:
        cli.success(f"  '{source}' is up to date with {upstream}.")

    # Target branch: main is not checked out yet, so fast-forward its ref with
    # a refspec fetch (which refuses a non-fast-forward update). Catches a stale
    # local main early instead of at the 'git push origin main' rejection.
    main_status = sync_status("main", "origin/main")
    if main_status is None:
        cli.info("Note", "no local 'main' or 'origin/main'; nothing to sync")
    elif main_status[1] > 0:
        cli.warn(f"  Local 'main' is {main_status[1]} commit(s) behind origin/main.")
        cli.step("Fast-forward local 'main' to origin/main?")
        cli.run(["git", "fetch", "origin", "main:main"])
    else:
        cli.success("  'main' is up to date with origin/main.")

    # --- versions --------------------------------------------------------------

    cli.section("Versions")
    current_version = cli.capture(["uv", "version", "--short"])
    if not current_version:
        cli.die("Failed to read current version from uv.")
    cli.info("Current version", current_version)

    # Decide whether the version actually changes. A bump always changes it; an
    # explicit --version only changes it when it differs from the current one.
    if args.no_version:
        version_changed = False
    elif args.version:
        version_changed = args.version != current_version
        if not version_changed:
            cli.info("Note", "requested version matches current; version unchanged")
    else:
        version_changed = True

    if version_changed:
        print(f"  {cli.GRAY}Preview of the version change:{cli.RESET}")
        if use_bump:
            cli.run(["uv", "version", "--dry-run", "--bump", args.bump])
        else:
            cli.run(["uv", "version", "--dry-run", args.version])
    else:
        cli.info("Result", "version already set; update and release commit are skipped")

    # --- release steps ---------------------------------------------------------

    cli.section("Step: switch to main")
    cli.step(f"Switch from '{source}' to 'main'?")
    cli.run(["git", "switch", "main"])

    cli.section(f"Step: merge '{source}' into main")
    cli.step(f"Merge '{source}' into 'main'?")
    cli.run(["git", "merge", source])

    if version_changed:
        cli.section("Step: update version")
        cli.step("Apply the version change?")
        if use_bump:
            cli.run(["uv", "version", "--bump", args.bump])
        else:
            cli.run(["uv", "version", args.version])

        # Brief pause before reading back the version: writing pyproject.toml can
        # leave uv.exe momentarily busy on Windows, which causes errors on the
        # next call.
        time.sleep(1)

        version = cli.capture(["uv", "version", "--short"])
        if not version:
            cli.die("Failed to read new version from uv after update.")
        cli.info("New version", version)

        cli.section("Step: commit release")
        cli.step(f"Stage all changes and commit as 'Release v{version}'?")
        cli.run(["git", "add", "."])
        cli.run(["git", "commit", "-m", f"Release v{version}"])
    else:
        version = current_version

    cli.section("Step: tag release")
    cli.step(f"Create annotated tag 'v{version}'?")
    cli.run(["git", "tag", "-a", f"v{version}", "-m", f"Release {version}"])

    cli.section("Step: push main")
    cli.step("Push 'main' to origin?")
    cli.run(["git", "push", "origin", "main"])

    cli.section("Step: push tags")
    cli.step("Push tags to origin?")
    cli.run(["git", "push", "origin", "--tags"])

    cli.section(f"Step: return to '{source}'")
    cli.step(f"Switch back to '{source}'?")
    cli.run(["git", "switch", source])

    cli.section(f"Step: merge main into '{source}'")
    cli.step(f"Merge 'main' into '{source}'?")
    cli.run(["git", "merge", "main"])

    cli.section(f"Step: push '{source}'")
    cli.step(f"Push '{source}' to origin?")
    cli.run(["git", "push", "origin", source])

    # --- done ------------------------------------------------------------------

    cli.section("Done")
    cli.success(f"  Released v{version}.")
    cli.info("Current branch", cli.capture(["git", "branch", "--show-current"]))


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):  # fmt: skip
        print()
        sys.exit(130)
