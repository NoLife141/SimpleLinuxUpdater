# Release Smoke Checklist

[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

Run this checklist on a real target host before creating a release tag.

## Preconditions

- Fresh app instance reachable from another machine (IP access, not localhost-only)
- One reachable Debian/Ubuntu test server with valid credentials
- Known-good backup path and test credentials available

## 1) Setup and Login

1. Open `/setup` from a remote browser and create admin account.
2. Confirm redirect to `/` and that authenticated navigation is visible.
3. Click logout and confirm redirect to `/login`.
4. Attempt login with wrong password and confirm error banner appears.
5. Login with correct password and confirm redirect to `/`.

Evidence to capture:

- Screenshot of successful `/setup` completion redirect
- Screenshot of invalid login error

## 2) Real Update Flow

1. Add one real server in `/manage`.
2. Start an update.
3. Confirm state transitions:
   - `updating` -> `pending_approval` (if packages are available)
   - `pending_approval` -> `upgrading` after approve
   - final state becomes `done` or explicit `error` (never hangs forever in `updating`)
4. If `pending_approval` appears, use both:
   - Approve all
   - Cancel (on a separate run)

Evidence to capture:

- Logs panel screenshot showing each transition
- Final status screenshot

## 3) Timeout Regression Guard

1. Set `DEBIAN_UPDATER_SSH_COMMAND_TIMEOUT_SECONDS=1`.
2. Restart app.
3. Trigger one update/autoremove action against a target expected to block/slow.
4. Confirm action exits to `error` with timeout message.
5. Confirm no server remains indefinitely in `updating`/`autoremove`/`sudoers`.

Evidence to capture:

- Log excerpt containing `timed out`
- Activity history entry for the failed action

## 4) Admin Safety Paths

1. Open `/admin`.
2. Verify metrics token status endpoint is reachable from UI.
3. Rotate metrics token and verify one-time reveal behavior.
4. Verify backup export requires passphrase confirmation.
5. Verify restore path validates file + passphrase.

Evidence to capture:

- Screenshot of Admin page sections
- Screenshot of backup/metrics actions completed

## 5) Final Gate

- `go test ./...` passes
- `npm run test:e2e` passes
- CI (`unit`, `race`, `cover`, `ui-e2e`) is green on the release commit
