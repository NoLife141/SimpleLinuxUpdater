[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Contributing

## Table of contents

- [Who we need](#who-we-need)
- [How to help](#how-to-help)
- [If you want to code](#if-you-want-to-code)
- [Build and test](#build-and-test)

## Who we need

If you run Linux servers (Debian/Ubuntu) or a homelab, your feedback is the most valuable input for this project. The goal is to make updates safer and more predictable in real environments.

Examples of useful contributors:

- Homelab users running a few machines and willing to test upgrades
- Linux admins managing multiple hosts and able to share operational expectations
- Anyone who can provide clear bug reports and reproduction steps

## How to help

You do not need to write code to contribute.

High-impact contributions:

- File bug reports with:
  - your OS (updater host + target host)
  - what you clicked / what command you ran
  - the relevant server logs from the UI
- Suggest features or defaults (for example: health check blocking policies, retry behavior, approval workflow)
- Share what you want to see in observability (which metrics and failure causes are actually useful)
- Improve the docs (clarity, missing steps, safer deployment guidance)

## If you want to code

If you want to implement a fix or feature:

- Open an issue first (or comment on an existing one) describing the change.
- Keep changes focused and add tests when behavior changes.
- Submit changes via a pull request.

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
