# Backend Refactor Plan

This plan is intentionally deferred work. The current app still works as a single-package Go service, but `webserver.go` now owns too many responsibilities: routing, request validation, SSH orchestration, audit emission, server persistence, policy APIs, maintenance guards, and dashboard refresh events.

## Goals

- Keep the public API and templates stable while reducing `webserver.go` into route wiring and shared middleware.
- Move business logic into testable services that can be exercised without a Gin router.
- Move SQL and file-backed persistence into repositories with narrow interfaces.
- Preserve the existing single-binary deployment and SQLite database.
- Avoid risky behavior changes during the split; each phase should have tests before and after.

## Proposed Package Layout

```text
cmd/simplelinuxupdater/
  main.go
internal/app/
  router.go
  config.go
  middleware.go
internal/auth/
  handlers.go
  service.go
  sessions.go
internal/servers/
  handlers.go
  service.go
  repository.go
internal/updates/
  handlers.go
  runner.go
  ssh.go
  health_checks.go
internal/policies/
  handlers.go
  scheduler.go
  matcher.go
  repository.go
internal/audit/
  handlers.go
  repository.go
  reports.go
internal/jobs/
  manager.go
  repository.go
internal/backup/
  handlers.go
  service.go
internal/events/
  broker.go
```

The first pass can keep `package main` if we want very small diffs. The second pass should introduce `internal/...` packages once the interfaces are clear.

## Phase 1 - Route Registry Without Behavior Changes

- Create a `registerRoutes(router *gin.Engine, deps AppDeps)` function.
- Group route registration by feature: auth, servers, updates, policies, audit, backup, observability, maintenance.
- Keep existing handler functions in place.
- Add a route inventory test that asserts critical endpoints still exist.
- Run `go test -count=1 ./...`, `go vet ./...`, and Playwright after the move.

## Phase 2 - Extract Audit And Reports

- Move audit event writes, listing, pruning, and Markdown report generation behind an `audit.Service`.
- Keep the current SQLite schema and response JSON untouched.
- Replace direct `writeAuditEvent` calls with `auditService.Record(...)`.
- Keep `notifyDashboardEvent` calls close to successful audit writes.
- Add service tests for metadata truncation, filtering, pruning, and report rendering.

## Phase 3 - Extract Job Manager

- Move `jobs.go` into an internal jobs package with a repository interface.
- Keep job status strings, JSON metadata, and retry semantics unchanged.
- Inject dashboard-event notification as a callback instead of calling global functions directly.
- Add tests for create, transition, compare-and-set, report lookup, and event callback dispatch.

## Phase 4 - Extract Server Inventory

- Move server CRUD, host uniqueness, password/key mutation, known_hosts operations, and tag parsing into `servers.Service`.
- Keep the product decision that one host has one SSH port in the inventory.
- Preserve the current API field names and validation errors where possible.
- Add service-level tests for host uniqueness, rename override migration, key fallback, and destructive mutation guards.

## Phase 5 - Extract Update Runner

- Move SSH dialing, command retries, CVE enrichment, precheck/postcheck, approval state, autoremove, and sudoers flows into `updates.Service`.
- Use small interfaces for SSH sessions and package/CVE lookups so tests do not need Gin.
- Keep the end-to-end runner tests because this path is the highest risk.
- Add targeted tests for timeout metadata, retry metadata, approval metadata, and report output.

## Phase 6 - Extract Scheduled Policies

- Move policy matching, blackout validation, missed-run replay, and scheduler ticks into `policies.Service`.
- Keep the newer targeting model: legacy `target_tag`, `include_tags`, `exclude_tags`, and `target_servers`.
- Add table-driven matcher tests for explicit servers, include/exclude tags, overrides, and no-target validation.
- Add scheduler tests for app timezone, overnight blackouts, missed ticks, and disabled policies.

## Phase 7 - Remove Remaining Globals

- Introduce an `AppDeps` struct with explicit dependencies: DB, job manager, audit service, server service, policy service, event broker, config.
- Replace package-level mutable state in tests with dependency-scoped fixtures.
- Keep compatibility helpers only where migration would be too noisy.
- Add a test helper that creates a fully isolated app instance per test.

## Phase 8 - Documentation And Operational Hardening

- Update `docs/architecture.md` with the final module map.
- Update contributor guidance with the new test fixture pattern.
- Add examples for adding a new API route, new audit event, and new scheduled-policy rule.
- Run a fresh manual smoke: setup, login, add host, audit, scheduled policy, backup export, backup restore, reports.

## Guardrails

- Do not mix refactor phases with new product behavior.
- Keep each phase mergeable and independently testable.
- Prefer duplicated glue during the transition over broad abstractions that are not proven yet.
- Keep existing JSON contracts stable unless a migration note and compatibility test are added.
- Never remove the existing high-level HTTP tests until the replacement service tests and Playwright coverage are in place.
