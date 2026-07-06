"""Interactively create an isolated git worktree on a fresh branch and open it in VS Code.

Intended for running multiple agents in parallel: each gets its own checkout
on its own branch, forked from current upstream. A VS Code workspace is
generated (copied from the repo's existing one where possible), forced to
point only at its own worktree, and kept out of git via the shared
.git/info/exclude.

Before creating the worktree it syncs the base branch: if your local base is
ahead of origin it offers to push (so the new worktree, forked from
origin/<base>, includes those commits), warns if the base has diverged, and
warns about uncommitted changes that can never transfer to a worktree.

Walks through the steps one at a time. Before each action it shows what is
about to happen and prompts for confirmation (y/n); answering 'n' aborts
without taking the remaining steps (anything already created is left in
place — remove_worktree.py cleans up a partial worktree). The output of
every git and uv/npm command is shown. Pass -y/--yes to answer every prompt
with 'y' for non-interactive use.

Usage:
    python scripts/new_worktree.py issue-42
    python scripts/new_worktree.py fix/login develop
    python scripts/new_worktree.py issue-42 --no-bootstrap
    python scripts/new_worktree.py issue-42 -y

Worktrees are created in a sibling '<repo>-wt' folder, on 'wt/<slug>' branches,
forked from 'develop' (or the base branch given as the second argument).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import _cli as cli

# Version of this helper script itself. Bump on every change so copies in other
# repos can be compared: patch = bugfix, minor = new flag/behavior, major =
# breaking CLI change.
__version__ = "1.2.2"


def slug_arg(value: str) -> str:
    """Validate the worktree slug.

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
        description="Create an isolated git worktree on a fresh branch and open it in VS Code."
    )
    parser.add_argument("slug", type=slug_arg, help="short name for the work, e.g. issue-42")
    parser.add_argument(
        "base",
        nargs="?",
        default="develop",
        help="branch to fork from (default: develop)",
    )
    parser.add_argument(
        "--no-bootstrap",
        action="store_true",
        help="skip the per-worktree dependency install",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="assume 'yes' to every confirmation prompt (non-interactive)",
    )
    return parser.parse_args()


def find_source_workspace(search_dirs: list[Path], exclude_name: str) -> Path | None:
    """Find a workspace file to use as a template.

    Prefers one already in the new worktree (a committed workspace, checked
    out from the branch) over one in the main repo root. Never returns the
    target file itself.

    Args:
        search_dirs: Directories to search, in priority order.
        exclude_name: File name of the workspace being generated.

    Returns:
        The template workspace path, or ``None`` if none was found.
    """
    for directory in search_dirs:
        for hit in sorted(directory.glob("*.code-workspace")):
            if hit.is_file() and hit.name != exclude_name:
                return hit
    return None


def link_or_copy(src: Path, dst: Path, label: str) -> None:
    """Symlink ``dst`` to ``src``, copying instead where symlinks are unavailable.

    Creating symlinks on Windows requires Developer Mode or elevation, so a
    plain copy is the fallback.

    Args:
        src: Existing file to link to.
        dst: Link (or copy) to create.
        label: Short name for progress output.
    """
    cli.echo(f"link {dst} -> {src}")
    try:
        dst.symlink_to(src)
    except OSError:
        shutil.copyfile(src, dst)
        cli.warn(f"  Symlink unavailable; copied {label} instead.")


def push_base(base: str) -> None:
    """Push the local base branch to ``origin``, handling a rejected push.

    A worktree forks from ``origin/<base>``, so the local base must be on origin
    for the new checkout to include its latest commits. The push streams its
    output; if origin rejects it (branch protection, diverged history, no
    network), the user is asked whether to create the worktree from origin as-is
    rather than the script aborting outright.

    Args:
        base: The base branch name, pushed as ``<base>:<base>``.
    """
    code = cli.run_ok(["git", "push", "origin", f"{base}:{base}"])
    if code != 0:
        cli.warn("  Push to origin was rejected (branch protection, diverged history, or network).")
        if not cli.confirm(f"Create the worktree from origin/{base} as-is anyway?"):
            cli.die("Aborted: push to origin failed.")


def main() -> None:
    """Run the interactive create-worktree flow."""
    args = parse_args()
    cli.set_assume_yes(args.yes)

    cli.info("Script version", __version__)
    print("")

    # --- resolve paths --------------------------------------------------------

    # rev-parse fails fast if not in a repo; --git-common-dir is the shared
    # .git, not the worktree stub, and may come back relative to the cwd.
    repo_root = Path(cli.capture(["git", "rev-parse", "--show-toplevel"]))
    common = cli.capture(["git", "rev-parse", "--git-common-dir"])
    common_dir = Path(common) if Path(common).is_absolute() else (Path.cwd() / common).resolve()
    repo_name = repo_root.name

    prefix = "wt/"
    branch = f"{prefix}{args.slug}"
    dir_slug = args.slug.replace("/", "-")
    wt_home = repo_root.parent / f"{repo_name}-wt"
    wt_path = wt_home / dir_slug
    ws_file = wt_path / f"{dir_slug}.code-workspace"

    # --- setup summary ----------------------------------------------------------

    cli.section("Worktree setup")
    cli.info("Slug", args.slug)
    cli.info("Branch", branch)
    cli.info("Base", f"origin/{args.base}")
    cli.info("Worktree", str(wt_path))
    cli.info("Workspace", str(ws_file))
    cli.info("Bootstrap", "no (--no-bootstrap)" if args.no_bootstrap else "yes")

    # --- guards -----------------------------------------------------------------

    if wt_path.exists():
        cli.die(f"{wt_path} already exists")
    if cli.capture(["git", "branch", "--list", branch]):
        cli.die(f"branch {branch} already exists")

    # --- step: fetch origin -------------------------------------------------------

    cli.section("Step: fetch origin")
    cli.step("Fetch 'origin'?")
    cli.run(["git", "fetch", "origin"])

    # --- step: sync base with origin ----------------------------------------------

    # The worktree forks from origin/<base>, so anything only in your local
    # checkout is missing from it. Uncommitted changes never transfer (a
    # worktree forks from a commit), and local commits don't transfer unless
    # pushed first. Surface both before creating the worktree.
    cli.section("Step: sync base with origin")

    if cli.capture(["git", "status", "--porcelain"]):
        cli.warn("  You have uncommitted changes in this working tree.")
        cli.warn("  They will NOT appear in the new worktree (it forks from a commit).")
        if not cli.confirm("Continue anyway?"):
            cli.die("Aborted: commit or stash your changes, then re-run.")

    remote_ref = f"origin/{args.base}"
    local_base = cli.capture_ok(["git", "rev-parse", "--verify", f"refs/heads/{args.base}"])
    remote_base = cli.capture_ok(["git", "rev-parse", "--verify", f"refs/remotes/{remote_ref}"])

    if local_base is None:
        cli.info("Base sync", f"no local '{args.base}' branch; will fork from {remote_ref}")
    elif remote_base is None:
        cli.warn(f"  origin has no '{args.base}' branch yet.")
        cli.step(f"Push local '{args.base}' to origin to create {remote_ref}?")
        push_base(args.base)
    else:
        ahead = int(cli.capture(["git", "rev-list", "--count", f"{remote_ref}..{args.base}"]))
        behind = int(cli.capture(["git", "rev-list", "--count", f"{args.base}..{remote_ref}"]))
        if ahead == 0:
            cli.info("Base sync", f"local '{args.base}' not ahead of {remote_ref}; nothing to push")
        elif behind == 0:
            cli.step(
                f"Local '{args.base}' is {ahead} commit(s) ahead of {remote_ref}. Push to origin?"
            )
            push_base(args.base)
        else:
            cli.warn(
                f"  Local '{args.base}' has diverged from {remote_ref} "
                f"({ahead} ahead, {behind} behind); not pushing (would need a force-push)."
            )
            cli.warn(f"  Worktree forks from {remote_ref}, missing your {ahead} local commit(s).")
            if not cli.confirm("Continue anyway?"):
                cli.die("Aborted: reconcile your base branch with origin, then re-run.")

    # --- step: create the worktree ------------------------------------------------

    cli.section("Step: create worktree")
    cli.step(f"Create worktree at '{wt_path}' on new branch '{branch}' from 'origin/{args.base}'?")
    wt_home.mkdir(parents=True, exist_ok=True)
    cli.run(["git", "worktree", "add", "-b", branch, str(wt_path), f"origin/{args.base}"])

    # --- step: generate the workspace ---------------------------------------------

    cli.section("Step: generate workspace")
    src_ws = find_source_workspace([wt_path, repo_root], ws_file.name)

    ws: dict[str, Any] | None = None
    if src_ws:
        try:
            # NB: VS Code workspace files are often JSONC (// comments,
            # trailing commas), which json.loads rejects. Fall back to a
            # minimal workspace rather than crashing.
            ws = json.loads(src_ws.read_text(encoding="utf-8-sig"))
            cli.info("Template", str(src_ws))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            cli.warn(f"  Could not parse {src_ws} ({exc}); generating a minimal workspace.")
            ws = None
    else:
        cli.info("Template", "(none found; generating a minimal workspace)")
    if not isinstance(ws, dict):
        ws = {"settings": {}}

    # Keep generated workspace files out of git. info/exclude lives in the
    # shared .git and is never committed, so this covers every worktree
    # without touching the tracked .gitignore.
    exclude = common_dir / "info" / "exclude"
    pattern = "*.code-workspace"
    existing = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
    need_exclude = pattern not in existing.splitlines()

    if need_exclude:
        cli.step(f"Write '{ws_file.name}' and add '{pattern}' to .git/info/exclude?")
    else:
        cli.step(f"Write '{ws_file.name}'?")

    # Guard: the workspace must point only at this worktree.
    ws["folders"] = [{"path": "."}]
    cli.echo(f"write {ws_file}")
    ws_file.write_text(json.dumps(ws, indent=2) + "\n", encoding="utf-8")

    if need_exclude:
        cli.echo(f"append '{pattern}' to {exclude}")
        exclude.parent.mkdir(parents=True, exist_ok=True)
        with exclude.open("a", encoding="utf-8") as handle:
            handle.write(pattern + "\n")

    if not args.no_bootstrap:
        # --- step: link config files ----------------------------------------------

        # Link local .vscode/launch.json and settings.json into the worktree.
        # Skip any that already exist: a committed .vscode file is checked out
        # by the worktree, and we don't clobber tracked files.
        links: list[tuple[Path, Path, str]] = []
        vscode_src = repo_root / ".vscode"
        vscode_dst = wt_path / ".vscode"
        for name in ("launch.json", "settings.json"):
            src = vscode_src / name
            dst = vscode_dst / name
            if src.exists() and not dst.exists():
                links.append((src, dst, f".vscode/{name}"))

        # Link every .env / .env.* file (testing, production, ...) so each
        # worktree shares the repo's single copy. Skip .env.example templates.
        for env_file in sorted(repo_root.iterdir()):
            name = env_file.name
            if not env_file.is_file():
                continue
            if name != ".env" and not name.startswith(".env."):
                continue
            if name.endswith(".example"):
                continue
            links.append((env_file, wt_path / name, name))

        cli.section("Step: link config files")
        if links:
            print(f"  {cli.GRAY}Files to link or copy into the worktree:{cli.RESET}")
            for _, _, label in links:
                print(f"  {cli.GRAY}- {label}{cli.RESET}")
            cli.step("Link/copy these files into the worktree?")
            for src, dst, label in links:
                dst.parent.mkdir(parents=True, exist_ok=True)
                link_or_copy(src, dst, label)
        else:
            print(f"  {cli.GRAY}Nothing to link.{cli.RESET}")

        # --- step: install dependencies ---------------------------------------------

        cli.section("Step: install dependencies")
        if (wt_path / "uv.lock").exists() or (wt_path / "pyproject.toml").exists():
            uv = shutil.which("uv")
            if uv:
                cli.step("Run 'uv sync' in the new worktree?")
                cli.run([uv, "sync"], cwd=wt_path)
            else:
                cli.warn("  'uv' not found on PATH; skipping dependency install.")
        elif (wt_path / "package-lock.json").exists():
            npm = shutil.which("npm")
            if npm:
                cli.step("Run 'npm ci' in the new worktree?")
                cli.run([npm, "ci"], cwd=wt_path)
            else:
                cli.warn("  'npm' not found on PATH; skipping dependency install.")
        else:
            note = "No uv project or npm lockfile found; nothing to install."
            print(f"  {cli.GRAY}{note}{cli.RESET}")

    # --- step: open VS Code -----------------------------------------------------

    cli.section("Step: open VS Code")
    code = shutil.which("code")
    if code:
        cli.step(f"Open VS Code with '{ws_file.name}'?")
        cli.run([code, str(ws_file)])
    else:
        cli.warn(f"  VS Code 'code' command not found; open manually: {ws_file}")

    # --- done ------------------------------------------------------------------

    cli.section("Done")
    cli.success(f"  Created worktree '{args.slug}'.")
    cli.info("Worktree", str(wt_path))
    cli.info("Branch", branch)
    cli.info("Workspace", str(ws_file))


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):  # fmt: skip
        print()
        sys.exit(130)
