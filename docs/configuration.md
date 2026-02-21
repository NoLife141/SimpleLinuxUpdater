[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Configuration

## Table of contents

- [Basic Auth](#basic-auth)
- [Storage paths](#storage-paths)
- [Retry policy](#retry-policy)
- [Post-update checks](#post-update-checks)
- [Known hosts handling](#known-hosts-handling)
- [Environment file (.env)](#environment-file-env)

## Basic Auth

Basic Auth is optional but strongly recommended.

Environment variables:

- `DEBIAN_UPDATER_BASIC_AUTH_USER`
- `DEBIAN_UPDATER_BASIC_AUTH_PASS`

Rules:

- If both are unset, Basic Auth is disabled.
- If only one is set, the server exits on startup with a configuration error.

Example:

```bash
export DEBIAN_UPDATER_BASIC_AUTH_USER=admin
export DEBIAN_UPDATER_BASIC_AUTH_PASS='change-me'
./webserver
```

When Basic Auth is enabled, all routes (including `/metrics` and `/observability`) require authentication.

## Storage paths

The updater persists state in SQLite and encrypts credentials (passwords and SSH keys) at rest.

Defaults:

- DB:
  - `/data/servers.db` if `/data` exists (Docker volume is typical)
  - `./data/servers.db` otherwise
- Encryption key file:
  - `/data/config.json` when using `/data`
  - `./data/config.json` otherwise

Optional override:

- `DEBIAN_UPDATER_DB_PATH`

Example:

```bash
export DEBIAN_UPDATER_DB_PATH=/var/lib/simplelinuxupdater/servers.db
./webserver
```

On first run, the app may import legacy `servers.json` if it exists, then uses SQLite going forward.

## Retry policy

Remote operations use exponential backoff retries for transient failures (SSH resets/timeouts, temporary transport issues, apt lock contention). Permanent failures (bad auth, host key verification, invalid config) fail fast.

Environment variables:

- `DEBIAN_UPDATER_RETRY_MAX_ATTEMPTS` (default `3`, allowed `1..10`)
- `DEBIAN_UPDATER_RETRY_BASE_DELAY_MS` (default `1000`, must be `> 0`)
- `DEBIAN_UPDATER_RETRY_MAX_DELAY_MS` (default `8000`, must be `> 0`)
- `DEBIAN_UPDATER_RETRY_JITTER_PCT` (default `20`, allowed `0..50`)

If invalid values are provided, the updater logs a warning and falls back to defaults.

## Post-update checks

After a successful upgrade, the updater can run health checks and optionally block completion.

Environment variables:

- `DEBIAN_UPDATER_POSTCHECKS_ENABLED` (default `true`)
- `DEBIAN_UPDATER_POSTCHECK_BLOCK_ON_APT_HEALTH` (default `true`)
- `DEBIAN_UPDATER_POSTCHECK_BLOCK_ON_FAILED_UNITS` (default `true`)
- `DEBIAN_UPDATER_POSTCHECK_REBOOT_REQUIRED_WARNING` (default `true`)
- `DEBIAN_UPDATER_POSTCHECK_CMD` (optional custom command; blocking when configured)

See [usage.md](usage.md) for behavior details and interpretation of failures.

## Known hosts handling

The app maintains SSH known-hosts entries and can scan/trust a host key from the UI before first connection.

Override search path:

- `DEBIAN_UPDATER_KNOWN_HOSTS` (colon-separated paths)

Default behavior:

- When using Docker with `/data`, the default known-hosts file is typically `/data/known_hosts`.
- When running locally, it is stored next to the DB in the local data directory.

## Environment file (.env)

For Docker, `.env` is not automatically loaded unless you pass it:

```bash
docker run --env-file .env -p 8080:8080 -v debian-updater-data:/data debian-updater-web
```
