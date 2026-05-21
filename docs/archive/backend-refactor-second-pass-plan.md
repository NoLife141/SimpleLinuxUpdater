# Backend Refactor Second Pass Plan

The first backend refactor pass is complete through Phase 8. The app now has route registration, `AppDeps`, package-main services, an isolated test fixture, `internal/jobs`, updated docs, and a live disposable-host smoke path.

This second pass is the package-boundary cleanup. Its goal is to move the current transitional `package main` services into real `internal/...` packages, remove compatibility wrappers and mutable globals, and keep the same public API, database schemas, job strings, audit events, templates, static assets, and single-binary deployment.

## Goals

- Move domain logic from `package main` into focused internal packages.
- Keep `main` as composition and process startup only.
- Replace package-level mutable globals with app-scoped dependencies.
- Keep SQLite schemas and public HTTP contracts stable.
- Keep each phase small, reviewable, independently testable, and safe to merge.
- Preserve the live disposable-host smoke path as the final operational gate.

## Target Package Layout

```text
cmd/simplelinuxupdater/
  main.go
internal/app/
  app.go
  router.go
  config.go
  middleware.go
  deps.go
internal/auth/
  handlers.go
  service.go
  sessions.go
  repository.go
internal/servers/
  handlers.go
  service.go
  repository.go
  known_hosts.go
  state.go
internal/updates/
  handlers.go
  service.go
  runner.go
  ssh.go
  health_checks.go
  cve.go
internal/policies/
  handlers.go
  service.go
  scheduler.go
  matcher.go
  repository.go
internal/audit/
  handlers.go
  service.go
  repository.go
  reports.go
internal/backup/
  handlers.go
  service.go
  archive.go
internal/events/
  broker.go
internal/jobs/
  jobs.go
```

## Guardrails

- Do not mix package extraction with product features.
- Do not change route paths, JSON field names, auth/CSRF behavior, templates, static asset paths, audit event names, job kinds, job statuses, policy run statuses, or report download behavior.
- Do not change SQLite table or column definitions unless a phase explicitly adds a migration and compatibility tests.
- Keep `go test -count=1 ./...`, `go vet ./...`, `go test -race -count=1 ./...`, `go build -o webserver .`, and `npm run test:e2e` passing after every phase.
- Keep wrappers temporarily when a phase needs a small bridge; remove all wrappers in the final cleanup phase.
- Prefer package-level service tests for pure domain behavior and HTTP tests only for route/middleware/wire-shape behavior.

## Phase 0 - Baseline And Extraction Harness

Prepare the repository for package moves without changing runtime behavior.

Required work:

- Create a branch such as `codex/backend-second-pass-harness`.
- Add a route/wire contract test snapshot that covers critical protected and public endpoints.
- Add focused contract tests for audit report, job report, server CRUD, policy CRUD/settings/runs, update start/approve/cancel, backup export/status, and auth session flows.
- Add a short `docs/backend-refactor-second-pass-status.md` checklist that tracks phase completion and validation results.
- Identify every `//lint:ignore U1000` compatibility wrapper and package-level mutable global that must disappear by the end.
- Confirm current validation passes before extraction starts.

Validation:

- `go test -count=1 ./...`
- `go vet ./...`
- `staticcheck ./...`
- `go build -o webserver .`
- `npm run test:e2e`

## Phase 1 - Events Package

Move dashboard event streaming out of `package main`.

Required work:

- Create `internal/events`.
- Move the client event broker type and methods into `internal/events`.
- Expose a small broker interface for `Publish(event string)` and SSE subscription.
- Inject the broker through `AppDeps` and route registration.
- Replace the global `dashboardEventBroker` with app-scoped broker ownership.
- Keep dashboard SSE path `/api/dashboard/events` and fallback behavior unchanged.

Tests:

- Broker subscribe/publish unit tests in `internal/events`.
- Route test proving `/api/dashboard/events` uses the injected broker.
- Dashboard summary/event smoke remains unchanged.

## Phase 2 - Audit Package

Move audit listing, writes, pruning, and report generation into `internal/audit`.

Required work:

- Create `internal/audit`.
- Move `AuditService`, list filters/results, metadata sanitization, truncation, pruning, and Markdown rendering.
- Add a repository interface and SQLite implementation for `audit_events`.
- Replace global `auditService` with app-scoped audit service.
- Convert `audit`, `auditWithActor`, `writeAuditEvent`, and report helpers into either methods or thin temporary adapters.
- Keep raw write behavior non-notifying and record behavior notifying only after successful writes.
- Keep `/api/audit-events`, `/api/audit-events/prune`, `/api/reports/audit/:id`, and job report output unchanged.

Tests:

- Move existing audit service tests into `internal/audit`.
- Keep HTTP tests for audit list/prune/report wire shapes.
- Verify dashboard notification only after successful record writes.

## Phase 3 - App Shell And Config Package

Create the real app composition boundary before moving high-coupling features.

Required work:

- Create `internal/app`.
- Move `AppDeps` or its successor into `internal/app`.
- Move router setup, trusted proxy config, middleware wiring, template/static setup, and route registration into `internal/app`.
- Keep `main` responsible only for process startup, DB opening through existing helpers until repositories move, scheduler start, and server listen/shutdown.
- Keep `setupRouter()` and `setupRouterWithDeps()` as temporary package-main test adapters if needed.
- Ensure no internal package imports `main`.

Tests:

- Route inventory tests against the new app constructor.
- App fixture isolation tests for DB, sessions, job manager, known_hosts, and event broker.
- Existing Playwright e2e unchanged.

## Phase 4 - Auth Package

Move auth and session behavior into `internal/auth`.

Required work:

- Create `internal/auth`.
- Move setup/login/logout/status/password/session handlers and session manager creation.
- Add a repository interface for `auth_users` and `sessions`.
- Move auth rate-limiter state behind an app-scoped dependency.
- Replace global `sessionManager` with app-owned session dependency.
- Preserve cookie name, session table schema, idle timeout behavior, secure-cookie env behavior, same-origin requirements, and response shapes.
- Keep setup/login native form fallback behavior.

Tests:

- Move auth service/session tests into `internal/auth` where possible.
- Keep HTTP tests for setup/login/logout/status/password/session clear.
- Verify two app fixtures do not share sessions or rate-limit state.

## Phase 5 - Backup Package

Move backup export/restore and restore barrier behavior into `internal/backup`.

Required work:

- Create `internal/backup`.
- Move backup archive creation, passphrase validation, encryption/decryption, config validation, DB replacement, known_hosts inclusion, and restore session invalidation.
- Move backup restore lock/barrier into app-scoped backup state.
- Keep backup file format, `.slubkp` download behavior, restore JSON response, and immediate restore semantics unchanged.
- Inject auth/session reset, DB reopen, server reload, known_hosts path, maintenance state, and dashboard/audit callbacks.

Tests:

- Backup archive/service unit tests in `internal/backup`.
- HTTP tests for `/api/backup/status`, `/api/backup/export`, and `/api/backup/restore`.
- Regression test that backup export is blocked while server actions are active.

## Phase 6 - Server Inventory Package

Move server inventory and host-key behavior into `internal/servers`.

Required work:

- Create `internal/servers`.
- Move `Server`, `ServerStatus`, inventory service, repository, known_hosts scan/trust/clear, tag parsing, port normalization, key/password mutation, and rollback helpers.
- Replace global `servers` and `statusMap` with an app-scoped server state object protected by its own mutex.
- Define interfaces needed by policies, updates, backup restore, dashboard summaries, and tests.
- Preserve host uniqueness ignoring port, one inventory port per host, per-server key/password behavior, global-key fallback hooks, active-action guards, and known_hosts write-path behavior.
- Remove server inventory compatibility wrappers after call sites use the package.

Tests:

- Move server inventory service tests into `internal/servers`.
- Keep HTTP tests for server CRUD, key/password mutation, hostkey scan/trust/clear, facts refresh, and duplicate/action guards.
- Verify rollback restores both server list and runtime status state.

## Phase 7 - Policy Package

Move scheduled policy persistence, validation, matching, and scheduler into `internal/policies`.

Required work:

- Create `internal/policies`.
- Move policy types, validation, matcher, blackout logic, due-slot detection, missed-tick replay, candidate priority, run records, repository, and scheduler.
- Replace global scheduler once/mutex/missed-tick state with service-owned state.
- Inject server snapshots, runtime status snapshots, maintenance state, backup restore lock, update-run execution, app timezone, audit, jobs, and clock.
- Preserve policy CRUD/settings/runs JSON, targeting model, run skip reasons, scheduler cadence, app-timezone semantics, and scan/update execution behavior.
- Remove policy compatibility wrappers after route and tests use package APIs.

Tests:

- Move policy service tests into `internal/policies`.
- Keep HTTP tests for policy CRUD/settings/runs/overrides.
- Keep integration tests for scheduled scan/update execution and missed-tick replay.

## Phase 8 - Update Package

Move update runner, SSH, health checks, CVE enrichment, approval, autoremove, and sudoers behavior into `internal/updates`.

Required work:

- Create `internal/updates`.
- Move update service, runner state, SSH abstractions, retry classification, apt parsing, selected package command building, precheck/postcheck, facts collection, CVE enrichment, approval/cancel behavior, autoremove, and sudoers enable/disable.
- Inject jobs, audit, server state, host-key callbacks, package/CVE helpers, policy run updates, dashboard events, clock, and maintenance checks.
- Keep job strings, status phases, logs, retry metadata, timeout metadata, approval metadata, CVE metadata, scheduled scan metadata, and report fields unchanged.
- Preserve route behavior for `/api/update/:name`, `/api/approve/:name`, `/api/approve-security/:name`, `/api/cancel/:name`, `/api/autoremove/:name`, `/api/sudoers/:name`, and `/api/sudoers/disable/:name`.
- Remove update compatibility wrappers once call sites use package APIs.

Tests:

- Move update service tests into `internal/updates`.
- Keep HTTP route tests for action start, approval, cancel, duplicate action, job IDs, and report rendering.
- Keep runner panic and race-sensitive tests.

## Phase 9 - Observability And Dashboard Package

Move dashboard summary, observability summary, metrics token, and Prometheus output behind an internal package.

Required work:

- Create `internal/observability` or keep this inside `internal/app` only if the dependency graph is simpler.
- Move observability cache and summary builders.
- Move metrics token storage and bearer-token route behavior if it is not part of auth.
- Inject audit repository, jobs, server state, facts repository, clock, and app settings.
- Preserve `/api/observability/summary`, `/api/dashboard/summary`, `/api/metrics/token`, and `/metrics` behavior.

Tests:

- Summary builder unit tests.
- HTTP tests for invalid windows, token rotate/reveal/clear, and metrics auth.
- Verify no cross-test cache leakage.

## Phase 10 - Repository And Schema Ownership

Consolidate schema setup and persistence ownership.

Required work:

- Each domain package owns its repository interface and SQLite implementation.
- Central app boot calls schema setup in a deterministic order.
- Remove ad hoc direct SQL from route handlers and unrelated packages.
- Keep schema byte-compatible unless a migration phase is created.
- Document table ownership in `docs/architecture.md`.

Tests:

- Repository tests per package.
- Fresh DB boot test that initializes all schemas and starts the app.
- Backup/restore test confirms all domain tables survive export/restore.

## Phase 11 - Final Global And Wrapper Removal

Remove remaining transitional state and adapters.

Required work:

- Remove all `//lint:ignore U1000` compatibility wrappers.
- Remove package-main globals for service singletons, session manager, job manager, dashboard broker, server state, maintenance state, policy missed ticks, observability cache, and SSH test hooks where practical.
- Move test hooks into package-local fixtures or interfaces.
- Delete obsolete package-main helper functions once their package equivalents are used.
- Ensure `staticcheck ./...` passes with no compatibility ignores.

Tests:

- Full suite and race suite.
- Fixture isolation tests for every mutable state area.
- Playwright e2e.

## Phase 12 - Documentation And Live Smoke

Update docs to describe the final architecture and prove the package split operationally.

Required work:

- Update `docs/architecture.md` with the final package map.
- Update `docs/contributing.md` with package ownership and fixture rules.
- Update `docs/backend-refactor-second-pass-status.md` with completed phases.
- Run the release smoke checklist against a disposable Ubuntu/Debian host.
- Record skipped steps and exact reasons if any smoke step cannot run.

Validation:

- `go test -count=1 ./...`
- `go vet ./...`
- `staticcheck ./...`
- `govulncheck ./...`
- `actionlint`
- `go test -race -count=1 ./...`
- `go build -o webserver .`
- `npm audit --audit-level=moderate`
- `npm run test:e2e`
- Disposable-host release smoke passes.

## Suggested PR Order

1. Phase 0 baseline/harness.
2. Phase 1 events package.
3. Phase 2 audit package.
4. Phase 3 app shell.
5. Phase 4 auth package.
6. Phase 5 backup package.
7. Phase 6 server inventory package.
8. Phase 7 policy package.
9. Phase 8 update package.
10. Phase 9 observability/dashboard package.
11. Phase 10 repository/schema ownership.
12. Phase 11 wrapper/global removal.
13. Phase 12 documentation/live smoke.

This order moves low-dependency packages first, saves the highest-coupling update/server/policy work for after the app boundary is stable, and leaves global removal until all call sites have a real package API.
