[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Installation

## Table of contents

- [Requirements](#requirements)
- [Install with Docker](#install-with-docker)
- [Install from source (binary)](#install-from-source-binary)
- [Cross-compile (Windows)](#cross-compile-windows)
- [Next steps](#next-steps)

## Requirements

- Go 1.26+ (only required if building from source)
- A Debian-based target host (Debian, Ubuntu, etc.) with `apt` and `sudo`
- Network access from the updater host to targets over SSH

## Install with Docker

Use the published image from GHCR (recommended):

```bash
cp .env-template .env
docker pull ghcr.io/nolife141/simplelinuxupdater:v0.1.5
docker run --env-file .env -p 8080:8080 -v debian-updater-data:/data ghcr.io/nolife141/simplelinuxupdater:v0.1.5
```

Open the UI:

- `http://localhost:8080`

Notes:

- The container stores the SQLite DB at `/data/servers.db` and the encryption key at `/data/config.json` when a volume is mounted.
- If you do not mount `/data`, state is not persisted.

Build locally (optional):

```bash
docker build -t debian-updater-web .
docker run --env-file .env -p 8080:8080 -v debian-updater-data:/data debian-updater-web
```

## Install from source (binary)

1. Build:

```bash
go build -o webserver webserver.go
```

2. Run:

```bash
./webserver
```

3. Ensure runtime assets are present:

- `templates/`
- `static/`
- Optional data directory (`./data/`) for persistence when not using `/data`

## Cross-compile (Windows)

From a Windows shell in the repo:

```bat
set GOOS=linux
set GOARCH=amd64
go build -o webserver webserver.go
```

Transfer `webserver` and the `templates/` and `static/` directories to the host you will run it from.

## Next steps

- Configure Basic Auth and storage paths: `configuration.md`
- Add servers and run updates: `usage.md`
