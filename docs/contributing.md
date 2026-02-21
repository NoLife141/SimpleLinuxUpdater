[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Contributing

## Table of contents

- [Development setup](#development-setup)
- [Build and test](#build-and-test)
- [Project conventions](#project-conventions)
- [Release process](#release-process)

## Development setup

Requirements:

- Go 1.26+

Clone the repo and run the server locally.

## Build and test

Build:

```bash
go build -o webserver webserver.go
```

Run tests:

```bash
go test ./...
go test -race -count=1 ./...
```

Optional checks:

```bash
go vet ./...
```

## Project conventions

- Use `gofmt` on Go files.
- Prefer table-driven tests with `t.Run`.
- Keep UI changes aligned with existing visual language.

## Release process

Releases are tag-driven (`vX.Y.Z`) via GitHub Actions.

Release gate checks include:

- `README.md` contains `Version: vX.Y.Z`
- `templates/index.html` contains `Version vX.Y.Z`
- `CHANGELOG.md` contains a `## [vX.Y.Z]` section

The release workflow publishes:

- GitHub release archives (Linux/macOS/Windows)
- Docker image to GHCR

Repository policy:

- Submit changes through pull requests (do not push directly to `main`).
