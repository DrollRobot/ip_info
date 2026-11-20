# Agent releasing instructions

- If the user asked you to read this file, treat that as them asking you to
  perform the prodedure described below. When replying to the user, do not describe
  every step taken, only decisions and further action required.

## Commit
- Review before writing commit messages: [AGENTS.COMMITTING.md](AGENTS.COMMITTING.md).
- Commit all untracked files.

## Refresh and audit dependencies

1. **Audit dependency floors for known-vulnerable versions:**
   ```
   uv audit --resolution lowest-direct
   ```
   For any advisory reported, raise that dependency's floor in
   `[project.dependencies]` (or its dependency group) to the fixed version.

2. **Refresh the lockfile** within existing pyproject.toml bounds. The
   pre-commit hooks run from the venv, so this updates them too:
   ```
   uv lock --upgrade
   ```

3. **Surface upgrades still blocked by version bounds:**
   ```
   uv tree --outdated --depth 1 --all-groups   # direct deps only
   ```
   Any package still annotated with a newer `(latest: ...)` version is held back
   by an upper bound in pyproject.toml (usually a new major release). Report
   these to the user for a decision. Do not raise version bounds without
   consulting the user.

4. **Audit for known vulnerabilities:**
   ```
   uv audit
   ```
   If a vulnerability is reported, fix it at the resolver-input layer:
   - Direct dependency: raise its version floor in `[project.dependencies]`
      (or its dependency group) to the patched version.
   - Transitive dependency: add a floor to `[tool.uv] constraint-dependencies`,
      with the advisory ID in a comment:
      ```toml
      [tool.uv]
      constraint-dependencies = [
         "somepkg>=1.2.3",  # GHSA-xxxx/CVE-2026-xxxx; prune when upstream requires it
      ]
      ```
   - Then re-lock and re-run until clean:
      ```
      uv lock
      uv audit
      ```
   If the new floor makes `uv lock` fail, another dependency still pins the
   vulnerable range. Upgrade that dependency if possible; otherwise stop and
   consult the user before considering `[tool.uv] override-dependencies`,
   which forces past the conflicting pin at the cost of ignoring it.

5. **Install the final lockfile and test:**
   ```
   uv sync --all-groups --all-extras     # install the refreshed lockfile
   ```
   Re-run the test suite as described in [AGENTS.TESTING.md](AGENTS.TESTING.md)
   before continuing.

## Update docs
```
uv run mkdocs build --strict          # build docs, fail on warnings
```
- Review all .md files in the root of the docs folder for accuracy or any new
   features that should be added.
- Don't review or modify files in docs/reference. (built by mkdocs)

## Review/Update README.md

- If there have been any user-facing changes to the package, review the README.md
   and consult the user if anything should be added/removed/updated.

## Update CHANGELOG.md

`CHANGELOG.md` in the repo root is the authoritative changelog.
Before proceeding, fetch and review <https://keepachangelog.com> to get the
current format rules. Do not rely on training data -- request a fresh copy every time.

**Deviation from Keep a Changelog:** version headings end with a title after the
date. Use this format in place of Keep a Changelog's `## [1.2.3] - 2026-01-31`:
```markdown
## [1.2.3] - 2026-01-31 - <title>
```
- `<title>` is a few words naming the release's main changes.

**How to update the changelog before tagging a new release**

1. **Find the previous tag** and collect every commit since then:
   ```powershell
   $prevTag = git describe --tags --abbrev=0   # most recent tag
   git log "$prevTag..HEAD" --oneline
   ```

2. **Break each commit message into individual details**, then evaluate each detail
   against the three changelog categories:
   - **Features** -- new or changed functionality a user can invoke (maps to Added,
     Changed, Deprecated, Removed).
   - **User-facing bugs** -- something that was broken and is now fixed (maps to Fixed).
   - **Security** -- vulnerabilities or security-relevant changes (maps to Security).

   If a detail does not clearly fit one of those three categories, discard it.
   Implementation details, refactors, test changes, linting fixes, and documentation
   updates are not included, unless they're the only notes for that release.

   Collect all surviving details, grouped by category, then use them to build the
   changelog section.

3. **Prepend** the new release section to `CHANGELOG.md` immediately after the
   `# Changelog` heading. Use today's date and the version about to be tagged.
   Do not rewrite or delete any previous releases.

## Commit any remaining files.

## Prompt user to finish the process.
- The user will run `push-new-tag-to-main` to update package version, merge to main,
   create tag, and push.
