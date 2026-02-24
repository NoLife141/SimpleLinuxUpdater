[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Security

## Table of contents

- [Summary](#summary)
- [Threat model](#threat-model)
- [Authentication model](#authentication-model)
- [Metrics endpoint protection](#metrics-endpoint-protection)
- [Encryption at rest](#encryption-at-rest)
- [Remote sudo behavior](#remote-sudo-behavior)
- [SSH key handling](#ssh-key-handling)
- [Recommended hardening](#recommended-hardening)

## Summary

This tool:

- Accepts SSH credentials (passwords and private keys) through the UI
- Can modify `/etc/sudoers.d/apt-nopasswd` on remote hosts when enabling passwordless apt
- Runs apt commands via `sudo` on remote hosts

Treat it as privileged infrastructure.

## Threat model

- Intended for trusted LAN/VPN environments only.
- No TLS termination by default; use a reverse proxy for HTTPS.
- Single-user local authentication is intended for small trusted teams/homelabs.

## Authentication model

SimpleLinuxUpdater uses:

- First-run setup at `/setup` to create one local admin user
- Argon2id password hashing (`auth_users` table in SQLite)
- Server-side sessions stored in SQLite (`sessions` table)
- Session cookies with `HttpOnly` and `SameSite=Lax`
- Response hardening headers:
  - `Content-Security-Policy`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `X-Frame-Options: DENY`
  - `Strict-Transport-Security` (HSTS) for HTTPS deployments

Setup enforces a password policy for the local admin user in `auth_users`:

- Minimum length: 10 characters
- Maximum length: 64 characters
- Must include at least one letter and one digit
- Username is required, maximum 64 characters, and limited to supported SSH-safe characters

Session hardening options:

- Set `DEBIAN_UPDATER_SESSION_COOKIE_SECURE=true` when running behind HTTPS.
- Optionally set `DEBIAN_UPDATER_SESSION_IDLE_TIMEOUT_HOURS` (hours). Default is `0`/unset, which means no additional idle timeout is applied.

## Metrics endpoint protection

`/metrics` is protected by a bearer token, separate from UI sessions.

Configure from the Manage page:

- Generate/rotate the Metrics API token in-app
- Store the one-time token output securely for your scraper
- Disable token to make `/metrics` return `404`

Scrapers must send:

```text
Authorization: Bearer <token>
```

Operational note:

- Auth and metrics rate limiting is in-memory per process. In multi-instance deployments, enforce global limits at the load balancer/API gateway.

## Encryption at rest

Secrets are stored encrypted in SQLite.

Files:

- SQLite DB: `/data/servers.db` (Docker) or `./data/servers.db` (local)
- Encryption key: `/data/config.json` (Docker) or `./data/config.json` (local)

If an attacker obtains both the database and the encryption key file (or the mounted volume), they can decrypt stored secrets.

## Remote sudo behavior

The updater uses `sudo apt ...` over SSH.

The UI can enable/disable passwordless apt by creating/removing:

- `/etc/sudoers.d/apt-nopasswd`

Manual sudoers rule (optional):

```bash
# As root, replace <user> with your SSH user
sudo visudo -f /etc/sudoers.d/apt-nopasswd
```

Add:

```text
<user> ALL=(root) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg, /usr/bin/fuser
```

Validate with:

```bash
sudo visudo -c
```

## SSH key handling

- SSH private keys can be uploaded through the UI (global or per-server).
- Uploaded key files are limited in size (64KB) to reduce accidental large uploads.

## Recommended hardening

- Do not expose the UI to the public internet.
- Restrict access with a VPN and/or reverse proxy controls.
- Use HTTPS and set `DEBIAN_UPDATER_SESSION_COOKIE_SECURE=true`.
- Store the generated Metrics API token in a secret manager and rotate it periodically.
- Protect the persisted volume (`/data`) like a secret.
