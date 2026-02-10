# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog, and this project uses Semantic Versioning for tags like `vMAJOR.MINOR.PATCH`.

## [Unreleased]

### Added

- Placeholder for upcoming changes.

## [v0.1.3] - 2026-02-10

### Changed

- Align release metadata with tag `v0.1.3` for release-gate verification.

## [v0.1.2] - 2026-02-10

### Changed

- Release workflow now publishes Windows artifacts as `.zip` while keeping `.tar.gz` for Linux/macOS.
- Clarify that runtime testing is currently performed on Linux amd64.

## [v0.1.1] - 2026-02-10

### Changed

- Bump release metadata and workflow/tooling alignment for Go 1.25 and release automation.

## [v0.1.0] - 2026-02-09

### Added

- Initial web UI for managing Debian-family apt updates over SSH.
- Per-server and global authentication support (password or SSH key).
- Upgrade approval flow, logs, and bulk operations.

### Security

- Encrypted storage for credentials in SQLite with a local config key.
