[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Architecture

## Table of contents

- [High-level components](#high-level-components)
- [Data storage](#data-storage)
- [Update runner lifecycle](#update-runner-lifecycle)
- [Audit events](#audit-events)
- [Observability](#observability)

## High-level components

- Web server: Go + Gin, server-rendered templates
- SSH layer: connects to targets and executes commands (per-action sessions)
- State: in-memory status map for live UI, persisted server config in SQLite
- UI: Status/Manage/Observability pages backed by JSON APIs

## Data storage

SQLite stores:

- Server inventory and encrypted credentials
- Audit events (`audit_events`)

An encryption key is stored in `config.json` alongside the DB (typically under `/data`).

Legacy import:

- On first run, the app may import `servers.json` (if present) and then uses SQLite going forward.

## Update runner lifecycle

Typical update:

1. Pre-checks run before `apt-get update`
2. `apt-get update`
3. Simulated upgrade to determine pending packages
4. Status becomes `pending_approval`
5. Approval or cancel occurs
6. Upgrade runs (`apt-get upgrade` or scoped `--only-upgrade` when security-only)
7. Post-update health checks run (if enabled)
8. Completion is recorded as `update.complete` audit event

## Audit events

Actions record status, message, and metadata. When Basic Auth is enabled, the actor is the Basic Auth username.

The audit store is auto-pruned (default retention 90 days).

## Observability

The observability dashboard and `/metrics` endpoint are derived from `update.complete` audit events:

- totals and success rate
- average duration (when duration metadata is present)
- failure-cause aggregation
