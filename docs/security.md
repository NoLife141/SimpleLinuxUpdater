[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Security

## Table of contents

- [Summary](#summary)
- [Threat model](#threat-model)
- [Authentication](#authentication)
- [Encryption at rest](#encryption-at-rest)
- [Remote sudo behavior](#remote-sudo-behavior)
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
- Basic Auth is optional and disabled unless configured.

## Authentication

Enable Basic Auth:

- `DEBIAN_UPDATER_BASIC_AUTH_USER`
- `DEBIAN_UPDATER_BASIC_AUTH_PASS`

When enabled, it protects the full UI and API surface, including `/metrics`.

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
- Use Basic Auth and strong passwords.
- Protect the persisted volume (`/data`) like a secret.
