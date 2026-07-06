# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
