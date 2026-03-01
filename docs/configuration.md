[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Configuration

## Table of contents

- [Authentication and sessions](#authentication-and-sessions)
- [Metrics API token](#metrics-api-token)
- [Backup and restore](#backup-and-restore)
- [Storage paths](#storage-paths)
- [Retry policy](#retry-policy)
- [Post-update checks](#post-update-checks)
- [Known hosts handling](#known-hosts-handling)
- [Environment file (.env)](#environment-file-env)

## Authentication and sessions

SimpleLinuxUpdater now uses a built-in single-user login flow:

- First run requires setup at `/setup` to create the initial local user.
- Passwords are stored as Argon2id hashes in SQLite (`auth_users` table).
- Authenticated UI/API access uses server-side sessions stored in SQLite.

Session defaults:

- Lifetime: 30 days
- Cookie: `HttpOnly`, `SameSite=Lax`
- Cookie `Secure`: configurable (recommended `true` behind HTTPS)

Environment variables:

- `DEBIAN_UPDATER_SESSION_COOKIE_SECURE` (`true|false`, default `false`)
- `DEBIAN_UPDATER_SESSION_IDLE_TIMEOUT_HOURS` (optional, integer hours; unset/`0` keeps default behavior)

## Metrics API token

`/metrics` is protected separately from UI sessions for machine-to-machine scraping.

Behavior:

- Disabled by default.
- Enabled only after generating a token from the Admin page.
- Token is shown once on create/rotate; if lost, rotate again.
- Scrape requests are rate-limited per client IP (in-memory, per app instance).

Prometheus must send:

```text
Authorization: Bearer <token>
```

## Backup and restore

Backup/restore is managed in-app from `/admin` (session-authenticated).

Behavior:

- Export requires a passphrase (minimum 12 characters).
- Backup payload is encrypted and downloaded as `.slubkp`.
- Backup contains:
  - `servers.db`
  - `config.json`
  - optional `known_hosts` (controlled by export toggle)
- Restore requires the backup file + passphrase and applies immediately (no restart required).
- Restore is a full replace of these files; current runtime state is reloaded.

What backup does not include:

- Reverse-proxy certificates/keys and external proxy config
- Container runtime settings outside the app data paths
- Any external secret manager state

## Storage paths

The updater persists state in SQLite and encrypts SSH credentials at rest.

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
- `DEBIAN_UPDATER_SSH_COMMAND_TIMEOUT_SECONDS` (default `300`, allowed `1..1800`)

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

Edit Server also provides **Known host management** actions:

- Check whether the current host/port is already present in `known_hosts`.
- Clear the matching known-host entry for the current host/port.
- Save bypasses redundant host-key trust prompts when the same host/port was already confirmed as trusted in the active edit session.

Override search path:

- `DEBIAN_UPDATER_KNOWN_HOSTS` (colon-separated paths)

Default behavior:

- When using Docker with `/data`, the default known-hosts file is typically `/data/known_hosts`.
- When running locally, it is stored next to the DB in the local data directory.

## Environment file (.env)

For Docker, `.env` is not automatically loaded unless you pass it:

```bash
docker run --env-file .env -p 8080:8080 -v debian-updater-data:/data ghcr.io/nolife141/simplelinuxupdater:v0.1.7
```
