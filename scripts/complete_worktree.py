"""Interactively complete a worktree: verify, push, and open a pull request.

Picks up where the agent leaves off. Once the feature/fix is committed and a
PR description has been written to PR.md, this walks through the remaining
steps one at a time. Before each action it shows what is about to happen and
prompts for confirmation (y/n); answering 'n' aborts without taking the
remaining steps. The output of every git and gh command is shown.

The procedure mirrors AGENTS.WORKTREE.md:
  1. Confirm we are on a wt/ branch in a worktree (never main/develop).
  2. Verify the working tree is clean — everything is committed. PR.md itself
     is exempt; it may stay uncommitted since it only feeds `gh pr create`.
  3. Resolve the PR base from the branch's UPSTREAM *before* pushing, since
     `git push -u` repoints tracking. Refuses to target main.
  4. Show the PR.md body and confirm the title.
  5. Push the branch with -u.
  6. Open the PR with `gh pr create --base <base> --body-file PR.md`.
  7. Report the PR URL and stop. The worktree is NOT cleaned up — that is
     left to the user, per AGENTS.WORKTREE.md.

Pass -y/--yes to answer every prompt with 'y' for non-interactive use.

Cross-device handoff (push on one device, open the PR on another) — for when
the device with the worktree has no authenticated gh, and nothing may leave the
repo:
  - On the device with the worktree, run --push-pr-to-notes. It verifies and
    pushes the branch, then attaches PR.md (with the base and title) as a
    per-slug git note (refs/notes/pr-body-<slug>) and pushes that note to
    origin. The note rides on the commit, so it never appears in the PR diff;
    one ref per slug means concurrent PRs never collide. No PR is created and
    gh is not required here.
  - On the other device, run --gh-from-notes --slug <slug> (creates the PR with
    gh) or --web-from-notes --slug <slug> (opens a prefilled PR form in the
    browser; no gh auth needed). Either fetches the branch and the note,
    recovers the base/title/body, creates the PR, and then offers to delete the
    note from origin.

Usage:
    python scripts/complete_worktree.py
    python scripts/complete_worktree.py --title "feat(auth): add SSO login" --draft
    python scripts/complete_worktree.py -y
    python scripts/complete_worktree.py --push-pr-to-notes
    python scripts/complete_worktree.py --web-from-notes --slug issue-42

Requirements:
    - Run from inside the worktree, on a wt/ branch with all work committed
      (PR.md itself does not need to be committed).
    - `git` and `gh` installed and authenticated (gh is NOT needed for
      --push-pr-to-notes or --web-from-notes).
    - A PR.md body file written by the agent at the worktree root.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import webbrowser
from pathlib import Path
from urllib.parse import quote

import _cli as cli

# Version of this helper script itself. Bump on every change so copies in other
# repos can be compared: patch = bugfix, minor = new flag/behavior, major =
# breaking CLI change. 1.1.0 ports the --push-pr-to-notes/--gh-from-notes/
# --web-from-notes cross-device handoff from Complete-WorkTree.ps1.
__version__ = "1.1.1"

# The cross-device PR-body handoff stores one note per slug
# (refs/notes/pr-body-<slug>) so concurrent PRs never share -- or force-push
# over -- a single ref. See notes_ref().
NOTES_REF_PREFIX = "pr-body"


def dirty_status_lines(status_lines: list[str], exempt_path: str | None) -> list[str]:
    """Filter ``git status --porcelain`` lines, ignoring the exempt PR body file.

    Args:
        status_lines: Output lines from ``git status --porcelain``.
        exempt_path: Repo-root-relative POSIX path allowed to stay uncommitted
            (the PR body file), or ``None`` when no path is exempt.

    Returns:
        The lines describing changes to any file other than ``exempt_path``.
    """
    dirty: list[str] = []
    for line in status_lines:
        if not line.strip():
            continue
        # Porcelain v1: two status letters, a space, then the path. Paths with
        # special characters are quoted; the plain strip covers the simple case.
        path = line[3:].strip().strip('"')
        if exempt_path is not None and path == exempt_path:
            continue
        dirty.append(line)
    return dirty


def parse_pr_note(content: str) -> tuple[str | None, str | None, str]:
    """Parse a pr-body note into its base, title, and body.

    The note is optional front-matter (``base:`` / ``title:`` lines) followed by
    a ``---`` separator and then the body. A note with no ``---`` is treated as
    all body.

    Args:
        content: The raw note text.

    Returns:
        ``(base, title, body)``; ``base`` and ``title`` are ``None`` when absent.
    """
    lines = content.splitlines()
    try:
        sep = lines.index("---")
    except ValueError:
        return None, None, content
    base: str | None = None
    title: str | None = None
    for line in lines[:sep]:
        base_match = re.match(r"base:\s*(.*)$", line)
        if base_match:
            base = base_match.group(1).strip()
            continue
        title_match = re.match(r"title:\s*(.*)$", line)
        if title_match:
            title = title_match.group(1).strip()
    return base, title, "\n".join(lines[sep + 1 :])


def origin_slug() -> str:
    """Parse ``owner/repo`` from origin's URL (SSH or HTTPS).

    Returns:
        The ``owner/repo`` portion, for building a github.com compare URL.
    """
    url = cli.capture(["git", "remote", "get-url", "origin"])
    match = re.search(r"github\.com[:/]+([^/]+)/(.+?)(?:\.git)?/?$", url)
    if not match:
        cli.die(f"Could not parse owner/repo from origin URL: {url}")
    return f"{match.group(1)}/{match.group(2)}"


def copy_to_clipboard(text: str) -> bool:
    """Best-effort copy to the OS clipboard via a platform tool (stdlib only).

    Args:
        text: Text to place on the clipboard.

    Returns:
        ``True`` if a clipboard tool ran successfully, ``False`` otherwise (the
        caller falls back to a file).
    """
    if sys.platform == "win32":
        command = ["clip"]
    elif sys.platform == "darwin":
        command = ["pbcopy"]
    else:
        command = ["xclip", "-selection", "clipboard"]
    try:
        result = subprocess.run(  # noqa: S603  (fixed argv list, no shell)
            command, input=text, encoding="utf-8"
        )
    except OSError:
        return False
    return result.returncode == 0


def open_web_pr(owner_repo: str, branch: str, base: str, title: str, body: str) -> None:
    """Open a github.com PR-compare page with the title and body prefilled.

    If the encoded URL is too long for a browser/GitHub to accept, fall back to
    opening the form with just the title and delivering the body another way
    (clipboard, or a temp file when no clipboard tool is available).

    Args:
        owner_repo: ``owner/repo`` for the compare URL.
        branch: The head branch to compare.
        base: The base branch to compare against.
        title: PR title to prefill.
        body: PR body to prefill.
    """
    compare_url = f"https://github.com/{owner_repo}/compare/{base}...{branch}?expand=1"
    enc_title = quote(title, safe="")
    full = f"{compare_url}&title={enc_title}&body={quote(body, safe='')}"
    if len(full) <= 8000:
        cli.echo("open <compare URL with prefilled title and body>")
        webbrowser.open(full)
        cli.success("  Opened the prefilled PR form in your browser.")
        return

    cli.echo("open <compare URL with prefilled title>")
    webbrowser.open(f"{compare_url}&title={enc_title}")
    if copy_to_clipboard(body):
        cli.warn(
            "  Body too long to prefill via URL; copied it to your clipboard - "
            "paste it into the form."
        )
    else:
        out = Path(tempfile.gettempdir()) / f"PR_body_{branch.replace('/', '-')}.md"
        out.write_text(body, encoding="utf-8")
        cli.warn(f"  Body too long to prefill via URL; saved it to {out} - paste it into the form.")


def notes_ref(slug: str) -> str:
    """Build the per-slug notes ref name (``pr-body-<slug>``).

    One ref per slug keeps concurrent PRs from sharing -- and force-pushing
    over -- each other's note. Slashes in the slug are flattened so the ref
    stays a single path segment.

    Args:
        slug: The worktree slug (the part after ``wt/``).

    Returns:
        The notes ref name (without the ``refs/notes/`` prefix).
    """
    return f"{NOTES_REF_PREFIX}-{slug.replace('/', '-')}"


def remove_pr_note(ref: str) -> None:
    """Delete a PR-body notes ref from origin and locally.

    Tolerates an already-gone ref (echoes the command, ignores the exit code)
    so cleanup is safe to run more than once.

    Args:
        ref: The notes ref name (without the ``refs/notes/`` prefix).
    """
    cli.echo(f"git push origin :refs/notes/{ref}")
    cli.exit_code(["git", "push", "origin", f":refs/notes/{ref}"])
    cli.echo(f"git update-ref -d refs/notes/{ref}")
    cli.exit_code(["git", "update-ref", "-d", f"refs/notes/{ref}"])


def cleanup_pr_note(ref: str, prompt: str) -> None:
    """Offer to delete the PR-body note from origin now the PR exists.

    Declining is not an abort -- the PR is already created -- so this prints how
    to remove the note later instead of stopping.

    Args:
        ref: The notes ref name (without the ``refs/notes/`` prefix).
        prompt: The yes/no question to show.
    """
    cli.section("Step: clean up PR body note")
    if cli.confirm(prompt):
        remove_pr_note(ref)
        cli.success("  Removed the PR body note from origin.")
    else:
        print(f"  {cli.GRAY}Left the note in place. Remove it later with:{cli.RESET}")
        print(f"    {cli.GRAY}git push origin :refs/notes/{ref}{cli.RESET}")


def parse_args() -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Complete a worktree: verify it is committed, push the branch, and open a PR."
    )
    parser.add_argument(
        "--title",
        help="PR title (default: subject of the last commit; always confirmed interactively)",
    )
    parser.add_argument(
        "--base",
        help="override the PR base branch (default: read from the branch's upstream)",
    )
    parser.add_argument(
        "--body-file",
        default="PR.md",
        help="path to the PR body file (default: PR.md at the worktree root)",
    )
    parser.add_argument("--draft", action="store_true", help="open the PR as a draft")
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="assume 'yes' to every confirmation prompt (non-interactive)",
    )
    parser.add_argument(
        "--push-pr-to-notes",
        action="store_true",
        help="device A: push the branch and attach PR.md as a 'pr-body' note (no PR, no gh)",
    )
    parser.add_argument(
        "--gh-from-notes",
        action="store_true",
        help="device B: fetch the branch and note for --slug, then create the PR with gh",
    )
    parser.add_argument(
        "--web-from-notes",
        action="store_true",
        help="device B: fetch the branch and note for --slug, then open a prefilled PR form",
    )
    parser.add_argument(
        "--slug",
        help="worktree slug (after 'wt/') for the --*-from-notes modes; "
        "defaults to the current wt/ branch",
    )
    return parser.parse_args()


def create_from_notes(args: argparse.Namespace) -> None:
    """Device B: recover a PR from a pushed branch and its pr-body note.

    Fetches the branch and the note, reads the base/title/body from the note,
    then either creates the PR with gh (``--gh-from-notes``) or opens a
    prefilled browser form (``--web-from-notes``).

    Args:
        args: Parsed command line.
    """
    slug = args.slug
    if not slug:
        current = cli.capture_ok(["git", "symbolic-ref", "--short", "HEAD"])
        if current and current.startswith("wt/"):
            slug = current.removeprefix("wt/")
    if not slug:
        cli.die("Specify --slug to identify the worktree branch (e.g. --slug issue-42).")
    branch = f"wt/{slug}"
    ref = notes_ref(slug)

    if args.gh_from_notes and shutil.which("gh") is None:
        cli.die(
            "gh not found on PATH. Use --web-from-notes to create the PR in the browser instead."
        )

    cli.section("Fetch branch and PR note")
    cli.run(["git", "fetch", "origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}"])
    cli.run(["git", "fetch", "origin", f"+refs/notes/{ref}:refs/notes/{ref}"])

    note_raw = cli.capture_ok(["git", "notes", f"--ref={ref}", "show", f"origin/{branch}"])
    if not note_raw:
        cli.die(
            f"No '{ref}' note found on origin/{branch}. "
            "Run --push-pr-to-notes on the device that has the worktree first."
        )
    note_base, note_title, note_body = parse_pr_note(note_raw)

    base = args.base or note_base or "develop"
    if base in ("main", "master"):
        cli.die(
            f"Refusing to target '{base}'. This project uses git flow; PRs go to "
            "develop. Pass --base to override deliberately."
        )

    title = args.title or note_title
    if not title:
        title = cli.capture(["git", "log", "-1", "--pretty=%s", f"origin/{branch}"])

    cli.info("Slug", slug)
    cli.info("Branch", branch)
    cli.info("PR base", base)
    cli.info("PR title", title)
    print()
    print(f"{cli.GRAY}{note_body.rstrip()}{cli.RESET}")

    if args.web_from_notes:
        cli.section("Step: open pull request (web)")
        cli.step(f"Open the prefilled PR form for '{branch}' into '{base}' in your browser?")
        open_web_pr(origin_slug(), branch, base, title, note_body)
        cleanup_pr_note(
            ref, f"Once you've created the PR in the browser, delete the '{ref}' note from origin?"
        )
        return

    # --gh-from-notes: create the PR with gh, body delivered via a temp file.
    cli.section("Step: open pull request")
    draft_note = " (draft)" if args.draft else ""
    cli.step(f"Open a PR from '{branch}' into '{base}'?{draft_note}")
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as handle:
        handle.write(note_body)
        body_file = handle.name
    try:
        create_args = ["gh", "pr", "create", "--base", base, "--head", branch, "--title", title]
        create_args += ["--body-file", body_file]
        if args.draft:
            create_args.append("--draft")
        output = cli.capture(create_args, echo_cmd=True)
    finally:
        Path(body_file).unlink(missing_ok=True)
    pr_url = output.splitlines()[-1].strip() if output else "(unknown)"

    cleanup_pr_note(ref, f"Delete the '{ref}' note from origin now the PR is created?")

    cli.section("Done")
    cli.success("  Pull request opened.")
    cli.info("PR", pr_url)
    cli.info("Base", base)


def push_pr_note(base: str, title: str, body_text: str, body_name: str, branch: str) -> None:
    """Device A: attach the PR body as a pr-body note and push it to origin.

    The note carries the resolved base and title as front-matter so the other
    device can recover them without any out-of-band communication.

    Args:
        base: Resolved PR base branch.
        title: Confirmed PR title.
        body_text: Raw PR body (PR.md contents).
        body_name: PR body file name, for the prompt.
        branch: The wt/ branch the note rides on.
    """
    slug = branch.removeprefix("wt/")
    ref = notes_ref(slug)
    cli.section("Step: attach PR body note")
    note_body = f"base: {base}\ntitle: {title}\n---\n{body_text}"
    cli.step(f"Attach {body_name} (with base/title) as a '{ref}' note and push it to origin?")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
        handle.write(note_body)
        note_file = handle.name
    try:
        cli.run(["git", "notes", f"--ref={ref}", "add", "--force", "--file", note_file, "HEAD"])
        cli.run(["git", "push", "origin", f"+refs/notes/{ref}:refs/notes/{ref}"])
    finally:
        Path(note_file).unlink(missing_ok=True)

    cli.section("Done")
    cli.success(f"  Pushed branch and PR body note for '{slug}'.")
    cli.info("Branch", branch)
    print()
    print(f"  {cli.GRAY}On the other device, create the PR with one of:{cli.RESET}")
    script = "python scripts/complete_worktree.py"
    print(f"    {cli.GRAY}{script} --gh-from-notes --slug {slug}{cli.RESET}")
    print(f"    {cli.GRAY}{script} --web-from-notes --slug {slug}{cli.RESET}")


def main() -> None:
    """Run the interactive verify-push-PR flow."""
    args = parse_args()
    cli.set_assume_yes(args.yes)

    cli.info("Script version", __version__)
    print("")

    if sum(bool(m) for m in (args.push_pr_to_notes, args.gh_from_notes, args.web_from_notes)) > 1:
        cli.die("Specify at most one of --push-pr-to-notes, --gh-from-notes, --web-from-notes.")

    # Device B never touches the local worktree; it works purely from origin.
    if args.gh_from_notes or args.web_from_notes:
        create_from_notes(args)
        return

    # --- gather state ----------------------------------------------------------

    cli.section("Worktree setup")

    branch = cli.capture_ok(["git", "symbolic-ref", "--short", "HEAD"])
    if not branch:
        cli.die("Not on a branch (detached HEAD?). Check out the wt/ branch first.")

    if branch in ("main", "master", "develop", "dev"):
        cli.die(
            f"On '{branch}'; this script is for wt/ feature branches, "
            "not the integration/release branch."
        )
    if not branch.startswith("wt/"):
        cli.warn(f"  Warning: branch '{branch}' does not look like a wt/ branch.")
        if not cli.confirm("  Continue anyway?"):
            sys.exit(1)

    repo_root = Path(cli.capture(["git", "rev-parse", "--show-toplevel"]))

    # Resolve the PR base. Read it from the branch's configured upstream,
    # because a later `git push -u` will repoint tracking to origin/<branch>
    # and lose it.
    base = args.base
    if not base:
        merge = cli.capture_ok(["git", "config", f"branch.{branch}.merge"])
        if not merge:
            cli.warn(f"  No upstream configured for '{branch}'.")
            base = cli.prompt_value("  Enter the PR base branch", default="develop")
        else:
            base = merge.removeprefix("refs/heads/")
        if base in ("main", "master"):
            cli.die(
                f"Refusing to target '{base}'. This project uses git flow; PRs go to "
                "develop. Pass --base to override deliberately."
            )

    cli.info("Worktree", str(repo_root))
    cli.info("Source branch", branch)
    cli.info("PR base", base)

    # --- PR body ---------------------------------------------------------------

    cli.section("PR body")
    body_path = Path(args.body_file)
    if not body_path.is_absolute():
        body_path = repo_root / body_path

    if not body_path.exists():
        cli.die(
            f"PR body file not found: {body_path}. "
            "Have the agent write the PR description to PR.md first."
        )
    body_text = body_path.read_text(encoding="utf-8-sig")
    if not body_text.strip():
        cli.die(f"PR body file is empty: {body_path}.")
    cli.info("Body file", str(body_path))
    print()
    print(f"{cli.GRAY}{body_text.rstrip()}{cli.RESET}")

    # --- title -----------------------------------------------------------------

    title = args.title or cli.capture(["git", "log", "-1", "--pretty=%s"])
    cli.section("PR title")
    title = cli.prompt_value("Confirm or edit the PR title", default=title)
    if not title.strip():
        cli.die("PR title cannot be empty.")

    # --- working tree status ---------------------------------------------------

    cli.section("Working tree status")
    cli.run(["git", "status", "--short", "--branch"])

    # The PR body file only feeds the PR, so it may stay uncommitted; exempt it
    # from the clean-tree check (when it lives inside the worktree).
    try:
        exempt = body_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        exempt = None
    status_lines = cli.capture(["git", "status", "--porcelain"]).splitlines()
    dirty = dirty_status_lines(status_lines, exempt)
    if dirty:
        print()
        cli.warn(
            f"  Working tree is not clean. Commit everything except {body_path.name} "
            "before completing the worktree."
        )
        cli.die("Uncommitted changes present; refusing to push.")
    cli.success(f"  Working tree is clean; all changes committed ({body_path.name} is exempt).")

    # --- existing PR guard (gh; skipped when only pushing the note) ------------

    existing_url = None
    if not args.push_pr_to_notes:
        cli.section("Existing PR check")
        existing_url = cli.capture_ok(["gh", "pr", "view", branch, "--json", "url", "--jq", ".url"])
        if existing_url:
            cli.warn(f"  A pull request already exists for '{branch}':")
            print(f"  {existing_url}")
            cli.warn("  Pushing will update it; a new PR will not be created.")
        else:
            cli.success("  No existing PR for this branch.")

    # --- push ------------------------------------------------------------------

    cli.section("Step: push branch")
    cli.step(f"Push '{branch}' to origin (with -u)?")
    cli.run(["git", "push", "-u", "origin", "HEAD"])

    # --- device A: attach the PR body as a note and stop -----------------------

    if args.push_pr_to_notes:
        push_pr_note(base, title, body_text, body_path.name, branch)
        return

    # --- open PR ---------------------------------------------------------------

    if existing_url:
        cli.section("Done")
        cli.success("  Branch pushed; existing PR updated.")
        cli.info("PR", existing_url)
        cli.info("Current branch", cli.capture(["git", "branch", "--show-current"]))
        print()
        print(f"  {cli.GRAY}Worktree left in place for you to clean up.{cli.RESET}")
        return

    cli.section("Step: open pull request")
    draft_note = " (draft)" if args.draft else ""
    cli.step(f"Open a PR from '{branch}' into '{base}'?{draft_note}")

    create_args = ["gh", "pr", "create", "--base", base, "--title", title]
    create_args += ["--body-file", str(body_path)]
    if args.draft:
        create_args.append("--draft")
    # Capture stdout for the URL; gh's progress messages stream on stderr.
    output = cli.capture(create_args, echo_cmd=True)
    print(output)
    pr_url = output.splitlines()[-1].strip() if output else "(unknown)"

    # --- done ------------------------------------------------------------------

    cli.section("Done")
    cli.success("  Pull request opened.")
    cli.info("PR", pr_url)
    cli.info("Base", base)
    cli.info("Current branch", cli.capture(["git", "branch", "--show-current"]))
    print()
    print(f"  {cli.GRAY}Worktree left in place for you to clean up.{cli.RESET}")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):  # fmt: skip
        print()
        sys.exit(130)
