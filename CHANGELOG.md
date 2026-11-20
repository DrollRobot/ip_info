# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ip-info-config` manages settings and provider API keys: `init`, `show`,
  `set-secret <provider>_api_key`, `delete-secret`, and more. Keys stay in the
  OS credential store; a per-user `config.toml` holds only their storage
  names.
- `scripts/migrate_keys.py`, a one-time script that moves 1.x API keys to
  their new location. It deletes each old key only after the new copy reads
  back correctly.
- `--profile` selects a settings profile, for separate keys per environment.
- API keys can come from environment variables
  (`IP_INFO_<PROVIDER>_API_KEY`), for headless runs.

### Changed

- **Breaking:** API keys move to a new keyring location. Run
  `scripts/migrate_keys.py` once after upgrading, or set the keys again with
  `ip-info-config`.
- **Breaking:** the lookup database moves from the package folder, which a
  reinstall replaced, to the per-user data folder; `db_path` in `config.toml`
  points it elsewhere. The old database is a cache and is not moved.
- **Breaking:** requires Python 3.14.10 or a later 3.14 release.
- The project now follows python_repo_template and syncs with it through
  `.template.toml`.

### Removed

- **Breaking:** the `ip_info_keys` command. Use `ip-info-config` instead.

## [1.8.0] - 2026-07-06

### Changed

- The output table now shows the full country name instead of the two-letter
  country code.
- When a provider's rate limit is reached, ip_info now waits until the next
  request is allowed and then continues, instead of silently skipping the
  query.
- Outbound provider requests now time out after 10 seconds instead of
  potentially hanging.

### Fixed

- Correct several provider response-parsing and local-database bugs.

[Unreleased]: https://github.com/DrollRobot/ip_info/compare/v1.8.0...HEAD
[1.8.0]: https://github.com/DrollRobot/ip_info/compare/v1.7.1...v1.8.0
