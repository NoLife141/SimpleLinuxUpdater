# Post-Refactor Stabilization Checklist

Use this checklist after the backend refactor second pass to validate that core product flows still work end to end. This pass should use a disposable local app database and disposable `known_hosts` unless explicitly testing a production instance.

## Scope

- Confirm the app still starts from a clean runtime state.
- Confirm app-scoped dependencies did not break auth, sessions, server inventory, policy scheduling, jobs, audit/reports, backup, observability, metrics, or dashboard events.
- Confirm key UI flows are still reachable and usable after the package-boundary refactor.
- Avoid destructive operations against real inventory. Use only temporary data for add/edit/delete/backup/export checks.

## Environment And Automated Gates

- [x] Working tree and branch state reviewed.
- [x] `go test -count=1 ./...`
- [x] `go vet ./...`
- [x] `staticcheck ./...`
- [x] `go test -race -count=1 ./...`
- [x] `go build -o webserver .`
- [x] `npm audit --audit-level=moderate`
- [x] `npm run test:e2e`
- [x] App starts with temp DB and temp `known_hosts`.

## UI Smoke With Computer Use

- [x] `/setup` loads on a fresh DB.
- [x] Setup creates an admin account and lands on the dashboard.
- [x] Logout redirects to `/login`.
- [x] Wrong password shows an error and does not log in.
- [x] Correct login returns to the dashboard.
- [x] Dashboard empty state and live polling/events label render without obvious layout breakage.
- [x] Navigation works for Status, Manage Servers, Observability, and Admin.
- [x] Manage page renders add-server form, global key panel, server table, and activity history areas.
- [x] Add disposable server with password auth.
- [x] Server appears in Manage and Status with secrets hidden.
- [x] Edit server tags/port/user and verify persistence after refresh.
- [x] Delete confirmation blocks incorrect typed confirmation for the disposable server. Covered by Playwright e2e typed-confirmation gate.
- [x] Host key scan/trust controls are reachable, but real trust is skipped unless using a disposable SSH target.
- [x] Admin page renders timezone, password/session, scheduled policy, backup, and metrics sections.
- [x] Invalid timezone save shows validation instead of navigating away. Covered by backend contract and e2e validation.
- [x] Disabled scan-only policy can be created for the disposable server.
- [x] Policy row reloads with target details and does not run while disabled.
- [x] Observability page renders the window controls and summary tables.
- [x] Backup export validation blocks missing/invalid passphrase input.
- [x] Metrics token rotate/disable controls are visible. Token generation was not executed during this smoke.
- [x] Destructive restore/prune/delete/global-key clear flows are not executed.

## API Contract Spot Checks

- [x] Protected API without session returns unauthorized.
- [x] Protected HTML without session redirects.
- [x] Same-origin protection rejects write requests without trusted headers.
- [x] `/api/servers` returns a list with expected top-level server fields.
- [x] `/api/auth/status` and `/api/auth/sessions` return expected JSON keys.
- [x] `/api/backup/status` returns expected JSON keys.
- [x] `/api/update-policies`, `/api/update-policies/settings`, and `/api/update-policies/runs` return expected JSON shapes.
- [x] `/api/audit-events` returns paginated items.
- [x] `/api/reports/audit/:id` returns Markdown.
- [x] `/api/dashboard/summary` and `/api/observability/summary` return JSON summaries.
- [x] `/metrics` remains blocked without a metrics bearer token.

## Findings

- No blocking refactor regression found in this stabilization pass.
- Resolved product-copy follow-up: disabled policies now explain that they do not match servers until enabled, instead of saying no server matches a tag/target.
- Browser environment note: the local Chrome Bitwarden extension displayed autofill overlays during password fields. This did not block app behavior and is not an application defect.

## Evidence

- Date: 2026-05-19 America/Toronto.
- Branch: `main`, based on `49f09c4 Finalize phase 12 docs and smoke results (#77)`.
- Dirty files before this checklist update: `docs/backend-refactor-second-pass-status.md` and this new checklist.
- Manual app runtime: `DEBIAN_UPDATER_DB_PATH=/tmp/slu-stabilization.hhtIPY/servers.db`, `DEBIAN_UPDATER_KNOWN_HOSTS=/tmp/slu-stabilization.hhtIPY/known_hosts`, `DEBIAN_UPDATER_SESSION_COOKIE_SECURE=false`, `./webserver`.
- Computer Use smoke: setup/login/dashboard/manage/admin/observability all rendered; disposable server `qa-local` was added, edited from `root@example.invalid:22` to `ubuntu@example.invalid:2222`, and shown on Status with secrets hidden.
- Policy smoke: disabled scan policy `QA disabled scan` and enabled future scan policy `QA enabled future scan` were created against `qa-local`; Status showed the next run for the enabled policy without starting a job.
- API spot checks: unauthenticated `/api/servers` returned `401`; unauthenticated `/manage` returned `302 /login`; missing same-origin write returned `403`; `/api/servers`, auth status/sessions, backup status, policy list/settings/runs, audit events/report, dashboard summary, and observability summary returned expected shapes; `/metrics` stayed blocked while disabled.
- Automated validation: `go test -count=1 ./...`, `go vet ./...`, `staticcheck ./...`, `go test -race -count=1 ./...`, `go build -o webserver .`, `npm audit --audit-level=moderate`, and `npm run test:e2e` passed. The first e2e rerun was blocked by the manual smoke server on port `8080`; after stopping it, all 11 Playwright tests passed.
