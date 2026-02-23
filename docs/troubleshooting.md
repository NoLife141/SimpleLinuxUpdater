[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Troubleshooting

## Table of contents

- [Setup and login issues](#setup-and-login-issues)
- [Forgotten admin password](#forgotten-admin-password)
- [Metrics authentication issues](#metrics-authentication-issues)
- [SSH host key issues](#ssh-host-key-issues)
- [APT locks and missing fuser](#apt-locks-and-missing-fuser)
- [Pre-check failures](#pre-check-failures)
- [Post-check failures](#post-check-failures)
- [CVE enrichment issues](#cve-enrichment-issues)
- [Database and file permissions](#database-and-file-permissions)

## Setup and login issues

Symptom: cannot create user, cannot log in, or repeated redirects to `/login`.

Checks:

- On first run, you must complete `/setup` before `/login` works.
- Password must meet policy requirements (length and complexity).
- Confirm your browser accepts cookies for the app host.
- If behind HTTPS, ensure `DEBIAN_UPDATER_SESSION_COOKIE_SECURE` matches your deployment:
  - `true` when served over HTTPS
  - `false` for local plain HTTP testing

## Forgotten admin password

For single-user deployments, password recovery is a reset flow:

1. Stop the application.
2. Remove the local auth record by deleting rows from `auth_users` (or drop/reset the whole application database if you prefer full reset).
3. Start the application again and revisit `/setup` to create a new admin user.

Impact:

- Deleting only `auth_users` resets login.
- Dropping the entire DB also removes saved servers, audit history, and app settings.

## Metrics authentication issues

Symptom: `/metrics` returns `401`.

Checks:

- `DEBIAN_UPDATER_METRICS_BEARER_TOKEN` is set and non-empty.
- Scraper sends `Authorization: Bearer <token>`.
- Token value matches exactly (including casing and whitespace).

## SSH host key issues

Symptom: SSH connection fails due to unknown host key or fingerprint mismatch.

Fix:

- Use the UI "Trust SSH host key now" to scan and trust the host key.
- Verify the fingerprint out-of-band before trusting.
- If you rotate host keys, update the known-hosts entry accordingly.

## APT locks and missing fuser

Symptom: pre-check fails due to lock contention.

Notes:

- The lock pre-check uses `sudo /usr/bin/fuser` and falls back to a process-based check if `fuser` is missing.
- Missing lock files are treated as no-lock (non-fatal).

Examples you may see in logs:

- Missing `fuser` (fallback path used):
  - `sudo: /usr/bin/fuser: command not found`
  - `sudo: unable to execute /usr/bin/fuser: No such file or directory`
- Lock file path missing (non-fatal/no-lock):
  - `/usr/bin/fuser: /var/cache/apt/archives/lock: No such file or directory`

## Pre-check failures

Common reasons:

- Insufficient free disk space on `/var` or `/`
- Disk space minimum is `1 GiB` (1048576 KB)
- APT/DPKG health failures (`dpkg --audit` or `apt-get check`)
- Lock contention

## Post-check failures

Common reasons:

- Failed systemd units after upgrade
- APT/DPKG health failures after upgrade

Blocking behavior is configurable; see [configuration.md](configuration.md).

## CVE enrichment issues

Symptom: CVE state becomes `unavailable`.

Possible causes:

- SSH dial failure in the enrichment goroutine
- Timeout running `apt-get changelog <package>`
- Package changelog is not available on the host

## Database and file permissions

Symptom: missing persistence or errors writing DB/config.

Fix:

- Ensure the process user can read/write the data directory.
- In Docker, mount a volume to `/data`.
