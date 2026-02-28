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

## [v0.1.7] - 2026-02-28

### Added

- Add built-in single-user authentication with first-run setup (`/setup`), login page (`/login`), and SQLite-backed session management.
- Add session-focused frontend auth helper (`static/auth.js`) and authenticated routing flow across UI pages.
- Add strict CSP template guard tests to prevent inline script/style regressions.
- Add encrypted in-app backup/restore for migration and disaster recovery:
  - backup export API and UI workflow
  - backup restore API and UI workflow
  - backup status API for DB/config/known_hosts visibility
- Add dedicated authenticated `/admin` page for sensitive operations.
- Add top-nav `Admin` link across authenticated pages for direct access.

### Changed

- Upgrade baseline modules/tooling for auth/session support and refresh release workflow inputs.
- Harden session handling defaults and security behavior (cookie/session policy updates).
- Migrate UI pages to strict CSP-compatible assets (`static/css/*`, `static/js/*`) and remove inline script/style reliance.
- Update docs (`installation`, `configuration`, `usage`, `security`, `architecture`, `deployment`, `troubleshooting`) to cover auth/session and backup/restore flows.
- Move Metrics API token management from `/manage` to `/admin`.
- Move Backup & Restore operations from `/manage` to `/admin`.
- Keep `/manage` focused on server lifecycle, global key management, and audit history.
- Refresh shared frontend helper usage to reduce duplicate JS utility logic.

### Fixed

- Apply CSP follow-up fixes for manage/login/status assets and related template checks.
- Improve setup/login/manage styling and JS behavior after CSP migration and backup/restore integration.
- Handle network exceptions in admin metrics/backup fetch flows with graceful UI fallbacks.
- Clear backup export/restore passphrase inputs in `finally` blocks to avoid leaving secrets in form state.
- Correct backup filename parsing regex to reliably extract and sanitize download names.

## [v0.1.6] - 2026-02-22

### Added

- Add dedicated documentation pages under `docs/` for installation, configuration, usage, deployment, security, troubleshooting, architecture, and contributing.
- Add a usage comparison section covering SimpleLinuxUpdater vs scripts vs Ansible-style automation.

### Changed

- Refresh README quick start to prioritize the official GHCR image and improve binary-release onboarding.
- Refine status page action layout to keep controls compact, stable, and easier to operate during `pending_approval`.
- Improve drawer approval actions with clearer emphasis and dynamic update counts.

### Fixed

- Keep drawer tab positions stable when pending-approval controls appear to avoid accidental misclicks.
- Harden inline `onclick` escaping in status/manage tables for safer server-name handling in HTML attribute context.
- Improve form control accessibility with explicit select focus/hover states and scoped table-button styling.

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
