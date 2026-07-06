# Agent releasing instructions

## Commit
- Commit any untracked files.

## Update precommit
```
# update precommit dependencies
uv run pre-commit autoupdate          # periodically update precommit dependencies
```

## Refresh and audit dependencies

1. **Refresh the lockfile** within existing pyproject.toml bounds:
   ```
   uv lock --upgrade                     # upgrade all deps within pyproject.toml bounds
   ```

2. **Surface upgrades still blocked by version bounds:**
   ```
   uv tree --outdated --depth 1 --all-groups   # direct deps only
   ```
   Any package still annotated with a newer `(latest: ...)` version is held back
   by an upper bound in pyproject.toml (usually a new major release). Report
   these to the user for a decision. Do not raise version bounds without
   consulting the user.

3. **Audit for known vulnerabilities:**
   ```
   uv audit                              # audit dependencies for known vulnerabilities
   ```
   - This mirrors the `Security audit` GitHub Actions workflow
     (`.github/workflows/audit.yml`), which runs `uv audit` and fails the build
     on any advisory. The refresh in step 1 often clears advisories on its own;
     this step handles whatever remains.
   - If a vulnerability is reported, fix it at the resolver-input layer:
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
     Then re-lock and re-run until clean:
     ```
     uv lock                               # re-resolve with the new floor
     uv audit                              # confirm no vulnerabilities remain
     ```
   - If the new floor makes `uv lock` fail, another dependency still pins the
     vulnerable range. Upgrade that dependency if possible; otherwise stop and
     consult the user before considering `[tool.uv] override-dependencies`,
     which forces past the conflicting pin at the cost of ignoring it.

4. **Install the final lockfile and test:**
   ```
   uv sync --all-groups                  # install the refreshed lockfile
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
   Do not rewrite or delete any existing sections.

## Commit any remaining files.

## Prompt user to push new tag
- The user will update pyproject.toml with the new version and regenerate uv.lock.
- The user will manage worktrees, branches, merging, tagging and pushing. At this point,
   the agent's job is complete.
