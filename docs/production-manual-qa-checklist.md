# Production Manual QA Checklist

Use this checklist to manually explore the production SimpleLinuxUpdater app and catch regressions or rough edges before they become real operational bugs.

For release gating with real SSH operations, use the disposable-target flow in [Release Smoke Checklist](release-smoke.md). This production checklist is for careful exploration of an existing app and should not mutate production hosts unless the tester explicitly intends that action.

## Before Testing

- [ ] Use a browser you normally use in production.
- [ ] Hard refresh once: `Cmd + Shift + R`.
- [ ] Open DevTools Console and watch for red errors.
- [ ] Pick one safe/non-critical server for update-related tests.
- [ ] Avoid `Approve all`, `Restore Backup`, `Delete Server`, and `Prune` unless you truly intend to perform them.
- [ ] For every bug, note the page, server name, action clicked, expected result, actual result, screenshot, and console error if any.

## Auth / Session

- [ ] Open the app while logged out.
- [ ] Expected: protected pages redirect to login.
- [ ] Log in with valid credentials.
- [ ] Expected: dashboard loads without errors.
- [ ] Try a wrong password.
- [ ] Expected: clear error, no login.
- [ ] Click Logout.
- [ ] Expected: session ends and protected pages require login again.
- [ ] Use browser Back after logout.
- [ ] Expected: protected data is not visible.

## Navigation / Layout

- [ ] Visit `Status`, `Manage Servers`, `Observability`, and `Admin`.
- [ ] Expected: active nav item is correct on each page.
- [ ] Resize browser narrow and wide.
- [ ] Expected: no overlapping text, clipped buttons, hidden tables, or unusable controls.
- [ ] Test with page zoom at 90%, 100%, and 125%.
- [ ] Expected: app remains usable.

## Status Dashboard

- [ ] Confirm all top metrics load: total hosts, pending approvals, active runs, failed hosts, security updates, and stale facts.
- [ ] Confirm polling state and last sync update over time.
- [ ] Search by server name, host, user, and tag.
- [ ] Expected: table results update correctly.
- [ ] Test status filter, auth filter, group by status, group by tag, and page size.
- [ ] Expected: counts, pagination, and visible rows stay consistent.
- [ ] Sort table columns where available.
- [ ] Expected: sort direction changes and rows reorder correctly.
- [ ] Select one row and then select all page.
- [ ] Expected: selected count/actions match the selected rows.
- [ ] Click a server row.
- [ ] Expected: selected host panel updates with correct server details.
- [ ] Check approval queue, active operations, failures, reboot required, risk exposure, audit trail, and command history panels.
- [ ] Expected: buttons inside mini panels open the correct server/drawer.

## Logs / Drawer

- [ ] Open Logs for an idle server.
- [ ] Expected: drawer opens, logs tab active, page behind does not scroll while drawer is open.
- [ ] Scroll logs.
- [ ] Expected: logs scroll inside drawer only.
- [ ] Click Copy logs.
- [ ] Expected: clipboard contains log text.
- [ ] Click Download logs.
- [ ] Expected: a `.txt` file downloads with the right server name/content.
- [ ] Press Escape.
- [ ] Expected: drawer closes.
- [ ] Click backdrop.
- [ ] Expected: drawer closes.

## Pending Updates Drawer

- [ ] Open a server in `pending_approval`.
- [ ] Expected: Pending updates tab is available and shows package/version/risk.
- [ ] Scroll the pending updates list.
- [ ] Expected: list scrolls inside drawer; dashboard behind does not move.
- [ ] Check summary badges: package count, security count, ready/scanning/unavailable/skipped.
- [ ] Wait while CVE enrichment runs.
- [ ] Expected: pending/ready counts update without breaking the list.
- [ ] Switch between Logs and Pending updates several times.
- [ ] Expected: both tabs remain usable.
- [ ] Confirm Approve buttons show correct counts.

## Server Actions

- [ ] Start update on a safe server.
- [ ] Expected: status changes to updating and logs begin.
- [ ] While update runs, try starting another action on the same server.
- [ ] Expected: app blocks duplicate action clearly.
- [ ] Wait for pending approval.
- [ ] Expected: server enters `pending_approval`; package list appears.
- [ ] Test Cancel on a safe pending update.
- [ ] Expected: status clears/cancels and audit entry appears.
- [ ] Only if intended: Approve security only.
- [ ] Expected: only security packages are approved, logs explain result.
- [ ] Only if intended: Approve all.
- [ ] Expected: upgrade continues, then final status/logs are clear.
- [ ] Test apt autoremove on a safe server.
- [ ] Expected: status/logs progress and finish or show useful error.
- [ ] Test password prompt by triggering an action needing a sudo password.
- [ ] Expected: empty password is blocked; Cancel closes cleanly.

## Manage Servers

- [ ] Add a test server with required fields.
- [ ] Expected: server appears in table and dashboard.
- [ ] Try missing name/host/user.
- [ ] Expected: validation error.
- [ ] Try duplicate server name or duplicate host.
- [ ] Expected: conflict/error, no duplicate row.
- [ ] Edit server name, host, port, user, and tags.
- [ ] Expected: changes persist after refresh.
- [ ] Upload per-server SSH key.
- [ ] Expected: key status updates, no key content displayed.
- [ ] Clear per-server key/password.
- [ ] Expected: auth badges/status update correctly.
- [ ] Check known host.
- [ ] Expected: shows trusted/missing state.
- [ ] Scan/trust host key only for a server you recognize.
- [ ] Expected: fingerprint confirmation appears before trust.
- [ ] Delete only a disposable test server.
- [ ] Expected: server disappears and related dashboard entries update.

## Global Key / Policy Overrides

- [ ] Upload global SSH key.
- [ ] Expected: global key status updates; secret is not displayed.
- [ ] Clear global key only if safe.
- [ ] Expected: global key status updates.
- [ ] Open Edit Server and check scheduled policy overrides.
- [ ] Expected: toggles load/save correctly for that server.

## Admin

- [ ] Check current app timezone display.
- [ ] Save invalid timezone.
- [ ] Expected: validation error.
- [ ] Save valid timezone, for example `America/Toronto`.
- [ ] Expected: success message and persisted value.
- [ ] Create a disabled test update policy.
- [ ] Expected: policy appears but does not run while disabled.
- [ ] Edit policy cadence, weekdays, time, package scope, and approval timeout.
- [ ] Expected: summary updates and saved values reload correctly.
- [ ] Add policy no-run windows using editor.
- [ ] Expected: rows save and reload.
- [ ] Apply blackout JSON with valid and invalid JSON.
- [ ] Expected: valid applies; invalid shows clear error.
- [ ] Check scheduled runs table.
- [ ] Expected: recent runs/empty state display clearly.
- [ ] Delete only a test policy.
- [ ] Expected: removed from list.

## Backup / Metrics

- [ ] Try backup export with mismatched passphrases.
- [ ] Expected: blocked with clear error.
- [ ] Export backup with a valid passphrase.
- [ ] Expected: encrypted `.slubkp` downloads.
- [ ] Do not restore in production unless this is an intentional disaster-recovery test.
- [ ] Check metrics token status.
- [ ] Generate token.
- [ ] Expected: token shown once and copy works.
- [ ] Test `/metrics` without token.
- [ ] Expected: unauthorized.
- [ ] Test `/metrics` with bearer token.
- [ ] Expected: Prometheus text output.
- [ ] Rotate token.
- [ ] Expected: old token stops working, new token works.
- [ ] Disable token.
- [ ] Expected: `/metrics` is blocked again.

## Observability / Audit

- [ ] Open Observability.
- [ ] Test `24h`, `7d`, and `30d` windows.
- [ ] Expected: KPIs and tables update consistently.
- [ ] Click Refresh.
- [ ] Expected: no duplicate/stale UI state.
- [ ] In Manage, test Activity History filters: actor, target, action, status.
- [ ] Test audit pagination.
- [ ] Expected: page count/results stay coherent.
- [ ] Avoid Prune unless you are okay deleting old audit rows.

## Good Bug Candidates To Watch For

- [ ] UI says success but data is not persisted after refresh.
- [ ] Button stays loading forever.
- [ ] Same server can start two actions at once.
- [ ] Logs stop updating while status still changes.
- [ ] Drawer/modal traps scroll or lets background scroll incorrectly.
- [ ] Approval counts disagree between dashboard, drawer, and table.
- [ ] Secret values appear in logs, audit, UI, or downloaded files.
- [ ] Error message is generic when the action failed for a clear reason.
