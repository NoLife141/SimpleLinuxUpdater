# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog, and this project uses Semantic Versioning for tags like `vMAJOR.MINOR.PATCH`.

## [Unreleased]

### Added

- No entries yet.

### Changed

- No entries yet.

### Fixed

- No entries yet.

## [v0.1.5] - 2026-02-21

### Added

- Add CVE-aware pending approval view with structured pending updates sorted security-first.
- Add asynchronous CVE enrichment from package changelogs with per-package states (`pending`, `ready`, `unavailable`, `skipped`).
- Add scoped approval actions for pending updates (`all` and `security-only`).
- Add observability dashboard page (`/observability`) and summary API (`/api/observability/summary`) with 24h/7d/30d windows.
- Add Prometheus-compatible metrics endpoint (`/metrics`) for update success rate, duration, and failure causes.

### Changed

- Align toolchain/dependency baseline with Go `1.26` and updated module dependencies.
- Improve status-page UX for pending approval and log/pending details presentation.
- Track richer update completion metadata for observability and approval scope reporting.

### Fixed

- Fix approval/cancel API semantics to return conflict when server is not in `pending_approval`.
- Harden CVE lookup flow with command timeout, safer command construction, and retry handling for enrichment SSH dial.
- Reduce security-source false positives by replacing broad `-security` substring matching with stricter suite-token matching.
- Improve timeout command handling to avoid lingering goroutine/buffer ownership issues in SSH command execution.

## [v0.1.4] - 2026-02-13

### Changed

- Lock pre-check now falls back to a process-based check (`apt`, `apt-get`, `dpkg`, `unattended-upgrade`) when `fuser` is unavailable.
- Update pre-check documentation to describe fallback behavior and troubleshooting.

### Fixed

- Fix regression where updates were aborted on hosts missing `/usr/bin/fuser` even when no lock contention existed.

## [v0.1.3] - 2026-02-13

### Added

- Add update pre-checks before `apt update` for disk space, apt/dpkg lock contention, and APT package health.
- Add targeted tests for pre-check behavior and early abort on pre-check failure.

### Changed

- Expand passwordless sudo bootstrap rule to include `/usr/bin/dpkg` and `/usr/bin/fuser` for new pre-check commands.
- Improve global SSH key loading resilience with retry/cached fallback behavior when SQLite is temporarily locked.
- Improve status logs UX and cancel behavior.
- Clear and collapse logs on cancel (single + bulk).
- Add fixed-height log panel with live auto-scroll handling.
- Colorize log lines for faster scanning.
- Add per-server log actions: copy and download.
- Refine log readability with subtle spacing and separators.
- Add persistent audit trail with Activity History UI, filtering, and 90-day auto-prune.
- Route audit event filtering tests through the production handler so dynamic WHERE, pagination, and total-count paths are exercised.

### Fixed

- Avoid copying `sync.Once` in test DB state preservation to respect no-copy semantics.
- Use single-quote shell escaping for sudoers `sh -c` command construction.
- Preserve audit metadata context when oversized by returning valid truncated JSON with a `_truncated` marker and warning log.

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
