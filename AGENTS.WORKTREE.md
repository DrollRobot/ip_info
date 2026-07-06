# AGENTS.WORKTREE.md

Instructions for working inside an isolated git worktree. Complements any
repo-level `AGENTS.md`; this file wins on worktree/PR matters.

## Assume

- You're in a worktree the user already opened, on branch `wt/<slug>`, forked
  from and tracking the remote base (normally `origin/develop`) that is the PR
  target — i.e. created with `git worktree add -b wt/<slug> origin/<base>`
  after a fetch.

## Testing

- Run tests as described in [AGENTS.TESTING.md](AGENTS.TESTING.md).

## Commits

- Agents should commit freely, ensuring all pre-commit checks pass.
- Commit messages should follow Chris Beam's guidance:
  https://chris.beams.io/posts/git-commit/
  Fetch the page at least once every session. Do not rely on memory for this.

## Completing the worktree

Pushing and opening the PR are **not** your job. Do **not** run `git push` or
`gh pr create`. The user will handle that.

When the user says the worktree is done ("done", "ship it", etc.), your job is to
leave it in this state:

**1. Commit everything**
Nothing uncommitted, nothing untracked. Commit all work in logical units with
conventional-commit messages. Make the most recent commit subject a clean
`type(scope): summary` — it stands in for the PR title.

**2. Write the PR description to `PR.md`**
- Write a real description to `PR.md` at the worktree root, using
  `.github/PULL_REQUEST_TEMPLATE.md` as a template, but write it in the style
  of a human summarizing the work, not a checklist for the contributor.
- Add `Closes #N` if the slug encodes an issue. Do not commit `PR.md`.

**3. Stop and tell the user**
Report that everything is committed and `PR.md` is written, then stop. The user
takes it from there.

## Review

- Never push, open a PR, run `scripts/complete_worktree.py`, merge, approve,
  enable auto-merge, force-push, or push to the base branch. Your job ends at
  "everything committed, `PR.md` written." Commit freely before then.
- Stay in this worktree. Don't touch sibling worktrees, the main checkout, hooks,
  or `.git/info/exclude`.
