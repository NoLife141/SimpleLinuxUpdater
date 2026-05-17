# UI Manual QA Checklist

Use this checklist for a disposable local run of the current build. Prefer a temp database and temp `known_hosts` file so the pass does not affect real configured hosts.

## Environment

- [ ] Build succeeds with `go build -o webserver .`.
- [ ] App starts on `http://127.0.0.1:8080` with a temp DB.
- [ ] Setup page loads when the temp DB has no admin account.
- [ ] Login succeeds after setup and redirects to the dashboard.

## Dashboard

- [ ] Header/nav renders without overlap at desktop size.
- [ ] Empty dashboard state is readable when no hosts exist.
- [ ] Live status label shows either `Live events` or `Live polling`.
- [ ] Dashboard data refresh does not visibly jump the table while interacting.
- [ ] Bulk approve requires typed confirmation `APPROVE ALL` before any request is sent.

## Manage Hosts

- [ ] Add-host form renders all fields and the global key panel.
- [ ] Server list table renders empty state and populated rows.
- [ ] Delete server prompt requires typing the server name.
- [ ] Audit table includes a `Report` column.
- [ ] Audit report links point to `/api/reports/audit/:id`.
- [ ] Audit prune requires typed confirmation `PRUNE`.
- [ ] Clear global key requires typed confirmation `CLEAR GLOBAL KEY`.
- [ ] Edit modal opens and traps focus.
- [ ] Policy override list updates when tags are edited before save.
- [ ] Explicit-server policy override matching is case-insensitive.
- [ ] Clear known host requires typed confirmation `host:port`.

## Admin

- [ ] App timezone section loads and can display the current timezone.
- [ ] Admin password form renders current, new, and confirmation fields.
- [ ] Password change errors show inline without navigating away.
- [ ] Logout all sessions requires typed confirmation `LOGOUT ALL`.
- [ ] Scheduled policy form accepts target tag, include tags, exclude tags, and explicit servers.
- [ ] Policy summary reflects all targeting fields.
- [ ] Saved policies render target details and matched server count.
- [ ] Policy delete requires typing the policy name.
- [ ] Scheduled runs table includes a `Report` column.
- [ ] Job report links point to `/api/reports/jobs/:id`.
- [ ] Backup restore requires typed confirmation `RESTORE`.
- [ ] Metrics rotate requires `ROTATE TOKEN`; disable requires `DISABLE METRICS`.

## Reports

- [ ] Audit report endpoint downloads Markdown.
- [ ] Job report endpoint downloads Markdown.
- [ ] Missing report IDs return a normal not-found response instead of a crash.

## Responsive/Visual Pass

- [ ] Dashboard, Manage, and Admin have no obvious clipped text at desktop size.
- [ ] Main controls remain reachable after scrolling.
- [ ] Tables remain readable and action buttons are visible.
- [ ] Confirmation prompts use exact required text and explain the action.

## Notes

- Do not run real host update, approve, backup restore, delete, or clear-key actions during manual QA unless intentionally testing against disposable data.
- For destructive confirmation checks, first type an incorrect value and verify the action is blocked.
