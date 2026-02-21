[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Deployment

## Table of contents

- [Docker (recommended)](#docker-recommended)
- [GHCR images](#ghcr-images)
- [Binary deployment](#binary-deployment)
- [Reverse proxy and HTTPS](#reverse-proxy-and-https)
- [Data persistence](#data-persistence)

## Docker (recommended)

Use a named volume for persistence:

```bash
docker run --env-file .env -p 8080:8080 -v debian-updater-data:/data ghcr.io/nolife141/simplelinuxupdater:v0.1.5
```

## GHCR images

Release tags publish images to GitHub Container Registry:

- `ghcr.io/nolife141/simplelinuxupdater:vX.Y.Z`
- `ghcr.io/nolife141/simplelinuxupdater:latest`

Example:

```bash
docker pull ghcr.io/nolife141/simplelinuxupdater:v0.1.5
```

## Binary deployment

If running as a binary, ensure the process can read/write the data directory and can read the `templates/` and `static/` directories at runtime.

Consider using a process supervisor (systemd) on the updater host.

Example systemd unit (adjust paths and env vars):

```ini
[Unit]
Description=SimpleLinuxUpdater
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/simplelinuxupdater
ExecStart=/opt/simplelinuxupdater/webserver
Restart=on-failure
Environment=DEBIAN_UPDATER_BASIC_AUTH_USER=admin
Environment=DEBIAN_UPDATER_BASIC_AUTH_PASS=change-me

[Install]
WantedBy=multi-user.target
```

## Reverse proxy and HTTPS

The app does not terminate TLS by default. For production:

- Put it behind a reverse proxy (nginx, Caddy, Traefik) for HTTPS
- Use Basic Auth and restrict access to your LAN/VPN

## Data persistence

Docker convention:

- `/data/servers.db`: SQLite DB
- `/data/config.json`: encryption key
- `/data/known_hosts`: SSH known-hosts (default)

If an attacker obtains both the SQLite DB and the encryption key file, stored secrets can be decrypted. See [security.md](security.md).
