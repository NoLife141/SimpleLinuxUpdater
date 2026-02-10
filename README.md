# SimpleLinuxUpdater

Version: v0.1.1

A web-based tool written in Go to manage apt updates on Debian-based Linux systems over SSH.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![CI](https://github.com/NoLife141/SimpleLinuxUpdater/actions/workflows/ci.yml/badge.svg)](https://github.com/NoLife141/SimpleLinuxUpdater/actions/workflows/ci.yml)

![UI demo](.github/assets/ALSU.gif)

## Features

- Manage multiple servers in a web UI (including custom SSH ports)
- Runs `apt update` and lists upgradable packages
- Prompts for approval before running `apt upgrade`
- On-demand `apt autoremove` per server or in bulk
- Shows live logs and status

## Requirements

- Go 1.25 or later (for building)
- Debian-based Linux system with `apt` and `sudo` access

### Sudo (Non-interactive)

The updater uses `sudo apt ...` over SSH. You can enable or disable passwordless apt in-app from the Status page (per server). Enabling modifies sudoers on the remote host by creating `/etc/sudoers.d/apt-nopasswd`; disabling removes it, both after you enter the sudo password once. Restrict who can access the UI and monitor changes (for example, check `/etc/sudoers.d/apt-nopasswd`).

Manual setup (optional):

```
# As root, replace <user> with your SSH user
sudo visudo -f /etc/sudoers.d/apt-nopasswd
```

Add this line:

```
<user> ALL=(root) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get
```

This allows non-interactive sudo for apt commands only. The app writes this rule under `/etc/sudoers.d/`. Test on a non-critical host first; optional hardening is to validate with `visudo -c` after changes. If you prefer broader access, adjust accordingly.

## Building

### Web Server Binary

#### On Windows (Cross-Compilation)

1. Install Go from https://golang.org/dl/
2. Open command prompt in the project directory
3. Run:
    ```
    set GOOS=linux
    set GOARCH=amd64
    go build -o webserver webserver.go
    ```
4. Transfer the `webserver` binary to your central server, along with `templates/` directory

#### On Linux

1. Clone or copy the code
2. Run `go build -o webserver webserver.go`

## Usage

### Quickstart (Docker)

```
docker build -t debian-updater-web .
docker run -p 8080:8080 -v debian-updater-data:/data debian-updater-web
```

The web server listens on `:8080` by default.

### Web UI Basic Auth (Recommended)

The app supports built-in HTTP Basic Auth (use this even behind your reverse proxy):

- `DEBIAN_UPDATER_BASIC_AUTH_USER`
- `DEBIAN_UPDATER_BASIC_AUTH_PASS`

If only one of these is set, the server exits at startup with a configuration error.

Example (binary):

```bash
DEBIAN_UPDATER_BASIC_AUTH_USER=admin \
DEBIAN_UPDATER_BASIC_AUTH_PASS='change-me' \
./webserver
```

Example (Docker):

```bash
docker run -p 8080:8080 \
  -e DEBIAN_UPDATER_BASIC_AUTH_USER=admin \
  -e DEBIAN_UPDATER_BASIC_AUTH_PASS='change-me' \
  -v debian-updater-data:/data \
  debian-updater-web
```

### Quickstart (Binary)

```
go build -o webserver webserver.go
./webserver
```

The web server listens on `:8080` by default.

### Web Server

The web interface allows managing multiple servers:

1. Add, edit, or delete servers via the management section.
   - Authentication can use a password, a per-server SSH key upload, or a global SSH key upload.
2. Trigger updates: the process will update packages, list available upgrades, and wait for approval.
3. Approve or cancel upgrades from the web interface.
4. View real-time logs and status.

### Tests and Release

Local test run:

```
go test ./...
```

Automated checks:

- CI on pushes/PRs to main runs tests: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
- Release workflow on tag `v*` runs tests, validates version/changelog metadata, builds release archives, and publishes a GitHub Release: [`.github/workflows/release.yml`](.github/workflows/release.yml)
- Release artifacts are cross-compiled for multiple platforms, but runtime testing is currently performed only on Linux amd64.

Release checklist (v0.1.0 and later):

- [ ] CI is green on main
- [ ] `README.md` `Version: vX.Y.Z` matches the release tag
- [ ] `templates/index.html` version pill matches the release tag
- [ ] `CHANGELOG.md` contains a `## [vX.Y.Z]` section
- [ ] Tag pipeline passes and publishes archives/checksums
- [ ] Dashboard loads and shows version pill
- [ ] Add/edit server works (including SSH port)
- [ ] Autoremove and sudoers setup work on a test host

### Web Server

1. Run `./webserver` on your central server.

2. Access the web interface at http://your-central-server:8080

3. Use the web interface to manage servers: add, edit, delete servers.

4. Trigger updates on servers. The web interface will show server status and allow triggering updates. Logs are displayed in real-time.

### Encryption Key (Auto-Generated)

Passwords are stored encrypted in SQLite. On first run, the app generates a 32-byte key and saves it to:

- `/data/config.json` (Docker with a volume)
- `./data/config.json` (local)

Optional DB path override:
- `DEBIAN_UPDATER_DB_PATH` (defaults to `/data/servers.db` if `/data` exists, otherwise `./data/servers.db`)

### Running with Docker

1. Ensure Docker Desktop is installed and running.

2. Build the Docker image:
   ```
   docker build -t debian-updater-web .
   ```

3. Run the container:
   ```
   docker run -p 8080:8080 debian-updater-web
   ```

4. Access the web interface at http://localhost:8080

5. To persist server configurations, use a named volume:
   ```
   docker run -p 8080:8080 -v debian-updater-data:/data debian-updater-web
   ```

6. If you use SSH keys, upload the private key from the web UI (global or per-server). The key is stored encrypted in the DB.

## SECURITY

This tool accepts SSH private keys via the web UI, can create `/etc/sudoers.d/apt-nopasswd` on remote hosts, and runs `apt` commands as root via `sudo`.

- The web UI must not be exposed to the public internet.
- Run it behind a VPN and/or a reverse proxy with authentication.
- Enable app-level Basic Auth via `DEBIAN_UPDATER_BASIC_AUTH_USER` and `DEBIAN_UPDATER_BASIC_AUTH_PASS`.
- Secrets (passwords and SSH keys) are stored encrypted in SQLite (`./data/servers.db` or `/data/servers.db`).
- The encryption key is stored in `./data/config.json` (local) or `/data/config.json` (Docker volume).
- If an attacker obtains both the SQLite database and the config file (or mounted volume), they can decrypt stored secrets.

## Threat Model / Limitations

- Basic Auth is optional and disabled unless configured via env vars.
- No TLS termination by default; use a VPN or reverse proxy for HTTPS.
- Intended for trusted LAN/VPN environments only.
- Designed for Debian-family hosts (e.g., Debian, Ubuntu, Linux Mint).

## Notes

- Requires sudo access for apt commands on the remote hosts
- Assumes amd64 architecture; adjust GOARCH if needed
- On first run, the app will import `servers.json` if present, then switch to SQLite
- Uploaded SSH key files are limited to 64KB
- Default known_hosts path is next to the DB (Docker default: `/data/known_hosts`); override with `DEBIAN_UPDATER_KNOWN_HOSTS` (colon-separated paths)
- In Add/Edit server forms, "Trust SSH host key now" scans the server key, shows its fingerprint, and appends it to known_hosts after confirmation

License

MIT © NoLife141
