# SimpleLinuxUpdater

Version: v0.1.5

SimpleLinuxUpdater is a self-hosted web UI that helps you manage apt updates on Debian-based servers over SSH. It provides an approval workflow, health checks, audit history, and basic observability so you can update hosts confidently without logging into each machine.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![CI](https://github.com/NoLife141/SimpleLinuxUpdater/actions/workflows/ci.yml/badge.svg)](https://github.com/NoLife141/SimpleLinuxUpdater/actions/workflows/ci.yml)

![UI demo](.github/assets/ALSU.gif)

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Overview

SimpleLinuxUpdater is designed for trusted environments (LAN/VPN). It connects to your servers via SSH and runs apt operations with sudo. Updates are gated behind `pending_approval`, and the UI surfaces checks, logs, and audit events.

## Features

- Multi-server management (custom SSH ports supported)
- `apt update` + pending package listing, gated behind approval
- Scoped approval during pending approval: approve all updates or security-only
- CVE-aware pending updates (best-effort changelog enrichment; security-first ordering)
- Pre-checks before upgrade and post-update health checks after upgrade
- On-demand `apt autoremove`
- Activity history (audit trail) stored in SQLite
- Observability: `/observability` dashboard and Prometheus `GET /metrics`

## Quick start

### Docker (official image)

```bash
cp .env-template .env
docker pull ghcr.io/nolife141/simplelinuxupdater:v0.1.5
docker run --env-file .env -p 8080:8080 -v debian-updater-data:/data ghcr.io/nolife141/simplelinuxupdater:v0.1.5
```

Open `http://localhost:8080`.

### Binary (prebuilt release)

Download the archive for your platform from GitHub Releases and run the included `webserver` binary. Release archives include `templates/`, `static/`, and `.env-template`.

Example (Linux amd64):

```bash
VERSION="0.1.5"
APP="SimpleLinuxUpdater_${VERSION}"
ARCHIVE="${APP}_linux_amd64.tar.gz"

curl -L -o "${ARCHIVE}" "https://github.com/NoLife141/SimpleLinuxUpdater/releases/download/v${VERSION}/${ARCHIVE}"
tar -xzf "${ARCHIVE}"
cd "${APP}"
cp .env-template .env
./webserver
```

## Documentation

- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Usage](docs/usage.md)
- [Deployment](docs/deployment.md)
- [Security](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Architecture](docs/architecture.md)
- [Contributing](docs/contributing.md)

Choosing between SimpleLinuxUpdater, scripts, and Ansible: see [docs/usage.md](docs/usage.md#how-simplelinuxupdater-compares-to-scripts-and-ansible).

## Security

This project can run apt commands via `sudo` on remote hosts and stores SSH credentials encrypted in SQLite. Do not expose the UI to the public internet. See [docs/security.md](docs/security.md).

## Contributing

See [docs/contributing.md](docs/contributing.md).

### Looking for help (Linux servers and homelabs)

If you have a Linux server, a homelab, or a small fleet of Debian/Ubuntu machines, your feedback and real-world testing is exactly what this project needs.

Ways you can help:

- Tell me what you want the tool to do next (feature requests and priorities)
- Report bugs with a short description and the relevant logs
- Share what hardware/OS you run (Debian/Ubuntu versions, VPS vs homelab) and what worked or did not
- Suggest safer defaults for checks, approvals, and retries
- Review the UI flow and propose improvements that reduce operational mistakes

## License

MIT. See [LICENSE](LICENSE).
