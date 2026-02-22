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

Session hardening options:

- Set `DEBIAN_UPDATER_SESSION_COOKIE_SECURE=true` when running behind HTTPS.
- Optionally set `DEBIAN_UPDATER_SESSION_IDLE_TIMEOUT_HOURS`.

## Metrics endpoint protection

`/metrics` is protected by a bearer token, separate from UI sessions.

Configure:

- `DEBIAN_UPDATER_METRICS_BEARER_TOKEN`

Scrapers must send:

```text
Authorization: Bearer <token>
```

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
- Use a strong `DEBIAN_UPDATER_METRICS_BEARER_TOKEN`.
- Protect the persisted volume (`/data`) like a secret.
