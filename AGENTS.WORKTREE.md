# AGENTS.WORKTREE.md

- If the user asked you to read this file, treat that as them asking you to
  perform the prodedure described below.

## Assume
- You're in a worktree the user already opened, on branch `wt/<slug>`, forked
  from and tracking the remote base (normally `origin/develop`) that is the PR
  target - i.e. created with `git worktree add -b wt/<slug> origin/<base>`
  after a fetch.

## Testing
- Run tests as described in [AGENTS.TESTING.md](AGENTS.TESTING.md).

## Commit
- Review before writing commit messages: [AGENTS.COMMITTING.md](AGENTS.COMMITTING.md).
- Commit all untracked files.

## Completing the worktree
Opening the PR is **not** your job. Do **not** run `gh pr create`.
When the user says the worktree is ready to close, your job is to leave it in
this state:

**1. Commit everything**
Commit all files in logical units according to instructions in:
[AGENTS.COMMITTING.md](AGENTS.COMMITTING.md).

**2. Write the PR description to `.local/PR.md`**
- **`.local/PR.md` must open with fenced front-matter that sets the PR title.**
  ```
  ---
  title: type(scope): summary
  ---
  <PR body...>
  ```
  Use a clean `type(scope): summary` for the title. The fence lines are metadata
  and are stripped before the body is sent to GitHub, so they never appear in
  the PR.
- For the body, write a real description using
  `.github/PULL_REQUEST_TEMPLATE.md` as a template, but in the style of a human
  summarizing the work, not a checklist for the contributor.
- Add `Closes #N` if the slug encodes an issue.

**3. Stop and tell the user**
Report that everything is committed and `.local/PR.md` is written, then stop. The user
takes it from there.

## Review
- Agents should never move the new code into the base branch; the human does that by
  opening the PR. Don't open a PR, run `complete-worktree`,
  or use any other workaround to get new code to the base branch. The agent's job
  ends at "everything committed, `.local/PR.md` written."
- Stay in this worktree. Don't modify any other branch without direct user approval.
