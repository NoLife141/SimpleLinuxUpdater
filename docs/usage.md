[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Usage

## Table of contents

- [Add and manage servers](#add-and-manage-servers)
- [Trust a host key](#trust-a-host-key)
- [Run updates with approval](#run-updates-with-approval)
- [CVE-aware pending approval](#cve-aware-pending-approval)
- [Logs and status](#logs-and-status)
- [Audit trail](#audit-trail)
- [Observability and metrics](#observability-and-metrics)
- [How SimpleLinuxUpdater compares](#how-simplelinuxupdater-compares-to-scripts-and-ansible)

## Add and manage servers

Use the Manage page to add, edit, or delete servers. Authentication options:

- Password per server
- SSH key per server (uploaded via UI)
- Global SSH key (uploaded via UI and reused when per-server key is missing)

## Trust a host key

In the Add/Edit server form, use "Trust SSH host key now" to:

- Scan the server host key
- Show its fingerprint for verification
- Append it to the known-hosts file after confirmation

This helps avoid first-connection failures due to unknown host keys.

## Run updates with approval

Typical workflow:

1. Trigger an update.
2. The updater runs pre-checks, then runs `apt-get update`.
3. It simulates the upgrade to list pending packages.
4. The server enters `pending_approval`.
5. You approve or cancel.

Approval actions:

- Approve all pending updates
- Approve security-only (runs a targeted `apt-get install --only-upgrade` for the approved security packages)

If you approve security-only and no security packages are detected, the upgrade is skipped and the update completes without applying changes.

### Pre-checks (fail fast)

Before `apt-get update`, update actions run mandatory pre-checks over SSH:

- Disk space: checks free space on `/var` and `/` and requires at least `1 GiB` (`1048576 KB`).
- Lock contention: checks apt/dpkg locks (uses `fuser` when available and falls back to process-based checks if `fuser` is missing).
- APT/DPKG health: runs `dpkg --audit` and `apt-get check`.

If any pre-check fails, the update stops before the approval flow and the server enters `error`.

### Post-update health checks

After an upgrade completes, the updater can run post-update health checks:

- APT/DPKG health (`dpkg --audit`, `apt-get check`)
- Failed systemd units (`systemctl --failed`)
- Reboot required marker (`/var/run/reboot-required`, warning only by default)
- Optional custom command (`DEBIAN_UPDATER_POSTCHECK_CMD`)

Blocking behavior is configurable; see [configuration.md](configuration.md).

The failed-units post-check takes a baseline snapshot before upgrade and compares it with the post-upgrade state to avoid flagging pre-existing failures as newly introduced.

## CVE-aware pending approval

During `pending_approval`, the UI shows a structured pending updates list:

- Security updates are prioritized first.
- CVE enrichment runs asynchronously so approval stays fast.
- CVE state values:
  - `pending`: lookup in progress
  - `ready`: CVE list populated
  - `unavailable`: lookup failed or timed out
  - `skipped`: outside lookup budget

Notes:

- CVE information is best-effort and advisory. Missing CVEs does not imply a package is not security-relevant.
- CVE lookup is derived from package changelogs (`apt-get changelog`) on the target host.

## Logs and status

The Status page shows current state and allows you to inspect logs. Logs are updated automatically as the updater runs.

### Passwordless apt toggle

From the Status page, you can enable or disable passwordless apt (per server). This creates or removes `/etc/sudoers.d/apt-nopasswd` on the target host so apt commands can be executed via sudo without prompting.

## Audit trail

The Manage page includes Activity History, backed by SQLite `audit_events`.

API:

```bash
curl -u admin:change-me "http://localhost:8080/api/audit-events?page=1&page_size=20&status=failure"
```

Notes:

- When Basic Auth is enabled, the actor is derived from the Basic Auth username.
- The audit store is automatically pruned (default retention is 90 days).

## Observability and metrics

UI:

- `GET /observability`

Summary API:

- `GET /api/observability/summary?window=24h|7d|30d`

Metrics:

- `GET /metrics` (Prometheus text format)

Observability KPIs are computed from `update.complete` audit events.

## How SimpleLinuxUpdater compares to scripts and Ansible

### Overview table

| Aspect                          | SimpleLinuxUpdater                           | Shell/script automation                | Ansible-style automation                     |
| ------------------------------- | -------------------------------------------- | -------------------------------------- | -------------------------------------------- |
| **Primary goal**                | Lightweight web UI for Debian/Ubuntu updates | Quick custom commands and scripts      | Full automation and configuration management |
| **Ease of setup**               | Low (fast UI setup)                          | Very low (simple scripts run anywhere) | Medium (install Ansible, manage inventories) |
| **Typical use case**            | Manual review and remote update control      | Ad-hoc tasks or one-off automation     | Repeatable automation across many hosts      |
| **Learning curve**              | Low                                          | Low (if you know shell basics)         | Medium-high (YAML, playbooks, roles)         |
| **Scale**                       | Small fleets / homelabs                      | Works on small sets, limited structure | Best for large infrastructures               |
| **Repeatability / idempotence** | Manual (UI driven)                           | Depends on script quality              | Designed for repeatable, idempotent runs     |
| **Scope**                       | Package updates only                         | Any shell task                         | Updates, configuration, orchestration        |

### Pros and cons

#### SimpleLinuxUpdater

Pros:

- Easy to install and use with a web UI
- No need to write scripts or playbooks
- Great for quickly managing updates from one dashboard

Cons:

- Specialized to apt updates
- Not built for broader automation workflows
- Not ideal for large automated infrastructures

#### Shell/script automation

Pros:

- Extremely flexible; write exactly what you need
- No additional tooling required apart from a shell and SSH
- Good for simple tasks or custom operations

Cons:

- Harder to maintain as complexity grows
- Less structure for large inventories of hosts
- Repeatability is up to the script author

#### Ansible-style automation

Pros:

- Structured, scalable automation for many tasks (not just updates)
- Ideal for configuration management and large fleets
- Uses playbooks and inventories for repeatable operations

Cons:

- Requires learning Ansible fundamentals (YAML, inventories)
- More setup and tooling overhead
- Overkill when all you need is a UI for Debian package updates

### When to choose what

- SimpleLinuxUpdater: if you want a simple web UI to manage Debian/Ubuntu updates without scripts or playbooks
- Shell/script automation: if you are comfortable with shell and want quick, custom control
- Ansible-style automation: if you need large-scale automation, configuration, and repeatability across environments
