[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Troubleshooting

## Table of contents

- [Basic Auth issues](#basic-auth-issues)
- [SSH host key issues](#ssh-host-key-issues)
- [APT locks and missing fuser](#apt-locks-and-missing-fuser)
- [Pre-check failures](#pre-check-failures)
- [Post-check failures](#post-check-failures)
- [CVE enrichment issues](#cve-enrichment-issues)
- [Database and file permissions](#database-and-file-permissions)

## Basic Auth issues

Symptom: startup error about invalid Basic Auth configuration.

Fix:

- Set both `DEBIAN_UPDATER_BASIC_AUTH_USER` and `DEBIAN_UPDATER_BASIC_AUTH_PASS`, or unset both.

## SSH host key issues

Symptom: SSH connection fails due to unknown host key or fingerprint mismatch.

Fix:

- Use the UI "Trust SSH host key now" to scan and trust the host key.
- Verify the fingerprint out-of-band before trusting.
- If you rotate host keys, update the known-hosts entry accordingly.

## APT locks and missing fuser

Symptom: pre-check fails due to lock contention.

Notes:

- The lock pre-check uses `sudo /usr/bin/fuser` and falls back to a process-based check if `fuser` is missing.
- Missing lock files are treated as no-lock (non-fatal).

Examples you may see in logs:

- Missing `fuser` (fallback path used):
  - `sudo: /usr/bin/fuser: command not found`
  - `sudo: unable to execute /usr/bin/fuser: No such file or directory`
- Lock file path missing (non-fatal/no-lock):
  - `/usr/bin/fuser: /var/cache/apt/archives/lock: No such file or directory`

## Pre-check failures

Common reasons:

- Insufficient free disk space on `/var` or `/`
- Disk space minimum is `1 GiB` (1048576 KB)
- APT/DPKG health failures (`dpkg --audit` or `apt-get check`)
- Lock contention

## Post-check failures

Common reasons:

- Failed systemd units after upgrade
- APT/DPKG health failures after upgrade

Blocking behavior is configurable; see `configuration.md`.

## CVE enrichment issues

Symptom: CVE state becomes `unavailable`.

Possible causes:

- SSH dial failure in the enrichment goroutine
- Timeout running `apt-get changelog <package>`
- Package changelog is not available on the host

## Database and file permissions

Symptom: missing persistence or errors writing DB/config.

Fix:

- Ensure the process user can read/write the data directory.
- In Docker, mount a volume to `/data`.
