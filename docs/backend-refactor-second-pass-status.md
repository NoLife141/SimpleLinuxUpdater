# Backend Refactor Second Pass Status

This checklist tracks the second backend refactor pass described in [backend-refactor-second-pass-plan.md](backend-refactor-second-pass-plan.md). Phase 0 establishes the safety harness; package extraction starts in Phase 1.

## Phase Status

- [x] Phase 0 - Baseline And Extraction Harness: complete on `codex/backend-second-pass-harness`
- [x] Phase 1 - Events Package: complete on `codex/events-package`
- [x] Phase 2 - Audit Package: complete on `codex/audit-package`
- [x] Phase 3 - App Shell And Config Package: complete on `codex/app-shell-config`
- [x] Phase 4 - Auth Package: complete on `codex/auth-package`
- [ ] Phase 5 - Backup Package
- [ ] Phase 6 - Server Inventory Package
- [ ] Phase 7 - Policy Package
- [ ] Phase 8 - Update Package
- [ ] Phase 9 - Observability And Dashboard Package
- [ ] Phase 10 - Repository And Schema Ownership
- [ ] Phase 11 - Final Global And Wrapper Removal
- [ ] Phase 12 - Documentation And Live Smoke

## Phase 0 Validation

Required:

- [x] `go test -count=1 ./...`
- [x] `go vet ./...`
- [x] `staticcheck ./...`
- [x] `go build -o webserver .`
- [x] `npm run test:e2e`

Broader gates:

- [x] `govulncheck ./...`
- [x] `actionlint`
- [x] `go test -race -count=1 ./...`
- [x] `npm audit --audit-level=moderate`

Live disposable-host smoke is not required for Phase 0 because this phase adds documentation and tests only.

## Phase 1 Validation

Required:

- [x] `go test -count=1 ./...`
- [x] `go vet ./...`
- [x] `staticcheck ./...`
- [x] `go build -o webserver .`
- [x] `npm run test:e2e`

Broader gates:

- [x] `go test -race -count=1 ./...`
- [x] `govulncheck ./...`
- [x] `actionlint`
- [x] `npm audit --audit-level=moderate`

Live disposable-host smoke is not required for Phase 1 because this phase only moves the dashboard event broker behind `internal/events`.

## Phase 2 Validation

Required:

- [x] `go test -count=1 ./...`
- [x] `go vet ./...`
- [x] `staticcheck ./...`
- [x] `go build -o webserver .`
- [x] `npm run test:e2e`

Broader gates:

- [x] `go test -race -count=1 ./...`
- [x] `govulncheck ./...`
- [x] `actionlint`
- [x] `npm audit --audit-level=moderate`

Live disposable-host smoke is not required for Phase 2 because this phase only moves audit persistence, listing, pruning, and Markdown rendering behind `internal/audit`.

## Phase 3 Validation

Required:

- [x] `go test -count=1 ./...`
- [x] `go vet ./...`
- [x] `staticcheck ./...`
- [x] `go build -o webserver .`
- [x] `npm run test:e2e`

Broader gates:

- [x] `go test -race -count=1 ./...`
- [x] `govulncheck ./...`
- [x] `actionlint`
- [x] `npm audit --audit-level=moderate`

Live disposable-host smoke is not required for Phase 3 because this phase only moves router/app-shell composition behind `internal/app`.

## Phase 4 Validation

Required:

- [x] `go test -count=1 ./...`
- [x] `go vet ./...`
- [x] `staticcheck ./...`
- [x] `go build -o webserver .`
- [x] `npm run test:e2e`

Broader gates:

- [x] `go test -race -count=1 ./...`
- [x] `govulncheck ./...`
- [x] `actionlint`
- [x] `npm audit --audit-level=moderate`

Live disposable-host smoke is not required for Phase 4 because this phase only moves auth/session behavior behind `internal/auth`.

## Compatibility Wrappers To Remove Later

These wrappers are intentionally retained after the first pass and are marked with `//lint:ignore U1000`. They should disappear by Phase 11 after package APIs replace all transitional call sites.

### Policy Wrappers And Handlers

- `update_policies.go`: `normalizeUpdatePolicy`
- `update_policies.go`: `updateUpdatePolicy`
- `update_policies.go`: `enrichPoliciesWithMatches`
- `update_policies.go`: `candidatePriority`
- `update_policies.go`: `createSkippedPolicyRun`
- `update_policies.go`: `rememberMissedUpdatePolicyTick`
- `update_policies.go`: `pendingMissedUpdatePolicyTicks`
- `update_policies.go`: `forgetMissedUpdatePolicyTick`
- `update_policies.go`: `processDueUpdatePolicySlot`
- `update_policies.go`: `handleUpdatePoliciesList`
- `update_policies.go`: `handleUpdatePolicyCreate`
- `update_policies.go`: `handleUpdatePolicyUpdate`
- `update_policies.go`: `handleUpdatePolicyRuns`
- `update_policies.go`: `handleUpdatePolicySettingsStatus`
- `update_policies.go`: `handleUpdatePolicySettingsUpdate`

### Report Wrappers And Handlers

- `update_reports.go`: `loadAuditEventByID`
- `update_reports.go`: `handleAuditReport`
- `update_reports.go`: `buildAuditMarkdownReport`
- `update_reports.go`: `buildJobMarkdownReport`
- `update_reports.go`: `handleJobReport`

### Dashboard And Server Action Wrappers

- `webserver.go`: `handleDashboardEvents`
- `webserver.go`: `handleDashboardSummary`
- `webserver.go`: `createServerActionJob`
- `webserver.go`: `updateServerKey`

## Mutable Package State To Move Later

This inventory is grouped by likely owning phase. Some package-level values are constants or compiled regex helpers and may remain package-owned after extraction; this list focuses on mutable app state, service singletons, and test hooks.

### App, DB, And Encryption State

- `internal/app`: owns Gin router composition, trusted proxy parsing, global middleware ordering, initialization ordering, template loading, static mounting, and route registration callback execution.
- `app_deps.go`: `AppDeps` remains a temporary main-package compatibility boundary for main-owned services until later package extractions.
- `webserver.go`: `db`, `dbOnce`
- `webserver.go`: `keyOnce`, `encryptionKey`
- `webserver.go`: `runtimeStateMu`
- `app_timezone.go`: `detectSystemTimezoneNameFunc`, timezone metadata paths, localtime path, and zoneinfo roots

### Auth And Session State

- `internal/auth`: owns auth service logic, auth/session repositories, session manager construction helpers, same-origin helpers, and auth rate limiter implementation.
- `auth_session.go`: `sessionManager`, `sessionManagerMu`
- `auth_session.go`: temporary default auth service and auth/setup/login/password rate limiter singletons remain until final app-scoped ownership cleanup.

### Job State

- `jobs.go`: `jobManager`, `jobManagerMu`

### Audit State

- `audit_service.go`: `auditService` is now only the temporary main-owned default singleton for `internal/audit.Service`; final ownership cleanup is deferred to Phase 11.
- `webserver.go`: `auditPruneTickerOnce`

### Server Inventory And Runtime State

- `webserver.go`: `servers`, `statusMap`, `mu`
- `server_inventory_service.go`: `serverInventoryService`
- `webserver.go`: `saveServersFunc`
- `webserver.go`: `globalKey`, `globalKeyMu`
- `webserver.go`: `knownHostsMu`, `scanHostKeyFunc`

### Update Runner And SSH Test Hooks

- `webserver.go`: `dialSSHConnection`, `dialSSHConnectionMu`
- `webserver.go`: `updateRunnerWG`

### Policy Scheduler State

- `update_policies.go`: `updatePolicySchedulerOnce`
- `update_policies.go`: `updatePolicyTickMu`
- `update_policies.go`: `updatePolicyMissedTickMu`
- `update_policies.go`: `updatePolicyMissedTicks`

### Backup And Maintenance State

- `backup_restore.go`: `backupRestoreMu`
- `backup_restore.go`: backup/restore runtime state
- `maintenance.go`: maintenance state and lock

### Dashboard, Observability, And Metrics State

- `webserver.go`: `dashboardEventBroker` is now only the temporary main-owned default singleton for `internal/events.Broker`; final ownership cleanup is deferred to Phase 11.
- `webserver.go`: `observabilityCache`, `observabilityCacheMu`
- `webserver.go`: `metricsBearerTokenHash`, `metricsBearerTokenHashMu`, `metricsBearerTokenHashLoaded`, `metricsBearerTokenHashDBPath`

## Phase 0 Contract Coverage

- Route inventory remains covered by `criticalRouteInventory`.
- Backend contract tests cover auth/middleware behavior, representative route groups, server list shape, auth/session shape, backup status/export shape, audit/job reports, policy list/create/settings/runs shape, and update approve/cancel route contracts.
