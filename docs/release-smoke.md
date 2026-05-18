# Release Smoke Checklist

[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

Run this checklist before creating a release tag. The smoke must use a disposable app database, disposable `known_hosts`, and a disposable Debian/Ubuntu SSH target. Do not use existing saved inventory entries unless the release owner explicitly confirms they are safe to mutate.

## Preconditions

- Fresh build from the release commit.
- Disposable app DB path and disposable `known_hosts` path.
- One reachable Debian/Ubuntu target host that may be updated, reboot-flagged, scanned, and have test audit/job records created.
- Target details recorded outside the repo:
  - host and SSH port;
  - username;
  - auth method, either password or private key;
  - sudo behavior, including whether a sudo password is required;
  - confirmation that approving updates is safe.
- Browser access to the app from the tester machine.

Suggested local app command:

```bash
go build -o webserver .
mkdir -p .tmp-smoke
rm -f .tmp-smoke/servers.db .tmp-smoke/known_hosts
: > .tmp-smoke/known_hosts
DEBIAN_UPDATER_DB_PATH=.tmp-smoke/servers.db \
DEBIAN_UPDATER_KNOWN_HOSTS=.tmp-smoke/known_hosts \
./webserver
```

## 1) Setup and Login

1. Open `/setup` and create the admin account.
2. Confirm redirect to `/` and authenticated navigation is visible.
3. Click logout and confirm redirect to `/login`.
4. Attempt login with the wrong password and confirm the error banner appears.
5. Login with the correct password and confirm redirect to `/`.

Evidence to capture:

- Screenshot of successful setup redirect.
- Screenshot of invalid login error.

## 2) Add Disposable Host and Trust Key

1. Open `/manage`.
2. Add the disposable target with a clearly disposable name, for example `release-smoke-target`.
3. Confirm missing required fields are rejected before saving the valid host.
4. Scan the host key.
5. Confirm the fingerprint with the release owner or target console.
6. Trust the host key and confirm it is written to the disposable `known_hosts` file.
7. Refresh the page and confirm the host remains saved with secrets hidden.

Evidence to capture:

- Screenshot of saved target row.
- Fingerprint and known-host status.

## 3) Real Update Flow

1. Start an update on the disposable target.
2. Confirm state transitions:
   - `updating` to `pending_approval` when packages are available;
   - `pending_approval` to `upgrading` after approval;
   - final state becomes `done`, `cancelled`, or explicit `error`, never stuck in an active state.
3. If updates are safe, approve the selected release-owner-approved scope.
4. If updates are not safe after scan, cancel the pending update and record the reason.
5. Confirm duplicate action attempts are blocked while the update is active.

Evidence to capture:

- Logs panel showing each transition.
- Final server status.
- Approval or cancel audit event.

## 4) Scheduled Policy Smoke

1. Create a disabled policy first and confirm it does not run.
2. Edit the policy to target only the disposable host using explicit `target_servers`.
3. Use scan-only execution mode unless the release owner explicitly approves scheduled update execution.
4. Confirm the policy list shows the disposable host in matched servers.
5. Set the policy time to the next minute in the app timezone, save it, and leave the app running until the scheduler tick passes.
6. Confirm the scheduled run record appears with a clear status and report link.

Evidence to capture:

- Policy summary showing explicit target.
- Scheduled run row and report link.

## 5) Reports, Audit, and Observability

1. Open Manage activity history and filter for the disposable target.
2. Open an audit Markdown report from `/api/reports/audit/:id`.
3. Open a job Markdown report from `/api/reports/jobs/:id`.
4. Open Observability and test `24h`, `7d`, and `30d` windows.
5. Confirm dashboard summary panels do not show stale active jobs after the run completes.

Evidence to capture:

- Audit report download.
- Job report download.
- Observability summary screenshot.

## 6) Backup Export

1. Open `/admin`.
2. Export a backup with a temporary passphrase and include `known_hosts`.
3. Confirm the `.slubkp` file downloads.
4. Do not restore over a non-disposable app instance. If restore must be tested, start another temp app DB and restore there.

Evidence to capture:

- Backup export success state.
- Whether `known_hosts` was included.

## 7) Timeout Regression Guard

Run this only against a target or command path that is safe to fail.

1. Stop the app.
2. Restart with `DEBIAN_UPDATER_SSH_COMMAND_TIMEOUT_SECONDS=1` and the same temp DB/known-hosts files.
3. Trigger one safe update or autoremove action expected to exceed the timeout.
4. Confirm the action exits to `error` with timeout metadata.
5. Confirm no server remains indefinitely in `updating`, `autoremove`, or `sudoers`.

Evidence to capture:

- Log excerpt containing the timeout.
- Activity history entry for the failed action.

## 8) Automated Final Gate

Required:

- `go test -count=1 ./...` passes.
- `go vet ./...` passes.
- `go test -race -count=1 ./...` passes.
- `go build -o webserver .` passes.
- `npm run test:e2e` passes.
- CI (`unit`, `race`, `cover`, `ui-e2e`) is green on the release commit.

Optional hardening checks when tools are available:

- `staticcheck ./...` passes.
- `govulncheck ./...` passes.
- `actionlint` passes.
- `npm audit --audit-level=moderate` passes.

## Smoke Result

Record the result in the release notes or pull request:

- App commit:
- Disposable app DB path:
- Disposable known-hosts path:
- Disposable target name:
- Target OS:
- Update action result:
- Scheduled policy result:
- Audit/report result:
- Backup export result:
- Skipped steps and exact reasons:
