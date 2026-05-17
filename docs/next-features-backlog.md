# Next Features Backlog

This backlog captures the next work after the May 17, 2026 review pass. Items already implemented in that pass are listed as shipped so future planning starts from the real state.

## Shipped In Current Pass

- Typed confirmations for destructive actions: server delete, audit prune, global key clear, known_hosts clear, backup restore, metrics token rotation/disable, policy delete, and logout-all-sessions.
- Event-driven dashboard refresh using server-sent events with polling fallback and reconnect backoff.
- Rich scheduled-policy targeting with legacy target tag, include tags, exclude tags, and explicit server names.
- Admin password rotation and server-side session clearing.
- Markdown reports for audit events and update jobs.
- Expanded backend tests for auth/session administration, advanced policy targeting, and report endpoints.
- Expanded Playwright coverage for policy targeting, report links, typed confirmations, password changes, and destructive manage/admin flows.

## P1 - High Value Near-Term Features

### Policy Dry Run Preview

Show a live preview of which servers a scheduled policy will target before saving it.

- API: `POST /api/update-policies/preview`
- Input: the same payload as create/update.
- Output: matched servers, excluded servers with reason, disabled-by-override servers, and validation warnings.
- UI: add a preview panel in the policy editor near the target fields.
- Tests: matcher unit tests plus Playwright coverage for include/exclude/explicit server previews.

### Update Run Detail Page

Turn Markdown reports into an in-app detail view for update jobs.

- Keep the Markdown download endpoint.
- Add `/admin/jobs/:id` or a modal from the scheduled run table.
- Show timeline, command phases, retries, actor, target, audit links, and raw logs.
- Add copy buttons for report ID and job ID.
- Tests: report endpoint tests plus Playwright for opening a run detail from Admin.

### Audit Event Detail Drawer

Add an audit detail drawer on the Manage page.

- Show pretty-printed metadata, related report download, actor, status, and target.
- Preserve the current table for scanning.
- Add filtering by date range and action presets.
- Tests: Playwright for opening the drawer and verifying metadata formatting.

### Safe Bulk Actions

Add selected-host bulk actions with a review step.

- Actions: scan, update security packages, approve pending security, refresh facts.
- Show selected servers, expected auth method, and per-host readiness before execution.
- Require typed confirmation for update/approve actions.
- Tests: API tests for partial failure behavior and Playwright for selection/confirmation.

## P2 - Reliability And Operations

### Notification Hooks

Support optional webhook notifications for completed updates, failed scheduled runs, and backup restores.

- Config: environment variables or admin UI for webhook URL and event types.
- Delivery: retry with backoff, redact secrets, store last delivery status.
- Tests: service tests with an HTTP test server.

### Maintenance Window Calendar

Improve global and policy blackouts into a calendar-like view.

- Show upcoming allowed and blocked windows per policy.
- Highlight overnight windows and timezone behavior.
- Add an API that returns computed windows for the next 14 days.
- Tests: timezone and overnight-window table tests.

### Host Health Trend

Store lightweight historical health snapshots.

- Capture package counts, security count, last scan result, and last update result.
- Show trends in Observability without turning SQLite into a metrics database.
- Add retention controls.
- Tests: repository tests for retention and summary aggregation.

### Backup Integrity Check

Add a backup verification mode that checks an uploaded backup without restoring it.

- API: `POST /api/backup/verify`
- Validate encryption, schema version, included sections, and restore compatibility.
- UI: show verification result before the destructive restore action.
- Tests: corrupted backup, wrong passphrase, old schema, valid backup.

## P3 - Technical Health

### Backend Module Split

Follow `docs/backend-refactor-plan.md` to split the current backend into route, service, repository, job, audit, update, policy, and event modules.

### Test Fixture Cleanup

Reduce global-state leakage in Go tests.

- Create a single `newTestApp(t)` fixture that handles DB, sessions, rate limiters, metrics token state, job manager, maintenance state, and server state.
- Convert new tests first, then older tests as files are touched.

### Frontend Module Cleanup

Break large page scripts into smaller modules after backend APIs settle.

- `admin.js`: policy editor, backup, metrics, auth sessions.
- `manage.js`: server table, edit modal, audit table, global key.
- Keep plain JS unless a bigger frontend migration is explicitly chosen.

## Later Ideas

- Per-host maintenance notes and owner fields.
- Policy templates for common Ubuntu/Debian fleet shapes.
- CSV export for audit events and scheduled run history.
- Read-only operator role separate from admin.
- Optional WebAuthn or TOTP second factor for admin login.
- Package allow/deny lists per scheduled policy.
- Post-update custom health checks per host tag.
