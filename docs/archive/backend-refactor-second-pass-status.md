# Backend Refactor Second Pass Status

This checklist tracks the second backend refactor pass described in [backend-refactor-second-pass-plan.md](backend-refactor-second-pass-plan.md). Phase 0 establishes the safety harness; package extraction starts in Phase 1.

## Phase Status

- [x] Phase 0 - Baseline And Extraction Harness: complete on `codex/backend-second-pass-harness`
- [x] Phase 1 - Events Package: complete on `codex/events-package`
- [x] Phase 2 - Audit Package: complete on `codex/audit-package`
- [x] Phase 3 - App Shell And Config Package: complete on `codex/app-shell-config`
- [x] Phase 4 - Auth Package: complete on `codex/auth-package`
- [x] Phase 5 - Backup Package: complete on `codex/backup-package`
- [x] Phase 6 - Server Inventory Package: complete on `codex/servers-package`
- [x] Phase 7 - Policy Package: complete on `codex/policies-package`
- [x] Phase 8 - Update Package: complete on `codex/updates-package`
- [x] Phase 9 - Observability And Dashboard Package: complete on `codex/observability-dashboard-package`
- [x] Phase 10 - Repository And Schema Ownership: complete on `codex/repository-schema-ownership`
- [x] Phase 11 - Final Global And Wrapper Removal: complete on `codex/final-global-wrapper-removal`
- [x] Phase 12 - Documentation And Live Smoke: complete on `codex/phase12-docs-smoke`

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

## Phase 5 Validation

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

Live disposable-host smoke is not required for Phase 5 because this phase only moves backup/export restore behavior behind `internal/backup`.

## Phase 6 Validation

Required:

- [x] `go test -count=1 -run 'TestServer|TestHostKey|TestKnownHosts|TestGlobalKey|TestAPIServers|TestServerInventory|TestBackendContract|TestRouteInventory' ./...`
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

Live disposable-host smoke is not required for Phase 6 because this phase only moves server inventory state, persistence, known_hosts, and SSH auth helper behavior behind `internal/servers`.

## Phase 7 Validation

Required:

- [x] `go test -count=1 -run 'TestPolicy|TestUpdatePolicy|TestScheduled.*Policy|TestDashboard|TestBackendContract|TestRouteInventory' ./...`
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

Live disposable-host smoke is not required for Phase 7 because this phase only moves scheduled policy persistence, matching, blackout handling, run records, missed-tick replay, and scheduler ownership behind `internal/policies`.

## Phase 8 Validation

Required:

- [x] `go test -count=1 -run 'TestUpdate|TestAutoremove|TestSudoers|TestApproval|TestCVE|TestPostcheck|TestScheduled.*Policy|TestRunnerJobSync|TestMarkdownReport|TestBackendContract|TestRouteInventory' ./...`
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

Live disposable-host smoke is not required for Phase 8 because this phase only moves update, autoremove, sudoers, approval/cancel, CVE helper, and scheduled scan ownership behind `internal/updates`.

## Phase 9 Validation

Required:

- [x] `go test -count=1 -run 'TestObservability|TestDashboard|TestMetrics|TestBackendContract|TestRouteInventory|TestAppDeps' ./...`
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

Live disposable-host smoke is not required for Phase 9 because this phase only moves observability summaries, dashboard summaries, metrics rendering, metrics token storage, and metrics summary cache ownership behind `internal/observability`.

## Phase 10 Validation

Required:

- [x] `go test -count=1 -run 'TestSchema|TestRepository|TestServerFacts|TestBackup|TestBackendContract|TestRouteInventory|TestAppDeps' ./...`
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

Live disposable-host smoke is not required for Phase 10 because this phase only moves SQLite schema creation/migration and server-facts repository ownership behind domain packages.

## Phase 11 Validation

Required:

- [x] `go test -count=1 -run 'TestAppDeps|TestBackendContract|TestRouteInventory|TestAuth|TestSession|TestServer|TestBackup|TestAudit|TestPolicy|TestUpdate|TestObservability|TestMetrics|TestJob' ./...`
- [x] `go test -count=1 ./...`
- [x] `go vet ./...`
- [x] `staticcheck ./...`
- [x] `go test -race -count=1 ./...`
- [x] `go build -o webserver .`
- [x] `npm run test:e2e`

Broader gates:

- [x] `govulncheck ./...`
- [x] `actionlint`
- [x] `npm audit --audit-level=moderate`

Live disposable-host smoke is not required for Phase 11 because this phase only removes compatibility wrappers and app-scopes default runtime dependencies.

## Phase 12 Validation

Required:

- [x] `go test -count=1 ./...`
- [x] `go vet ./...`
- [x] `staticcheck ./...`
- [x] `govulncheck ./...`
- [x] `actionlint`
- [x] `go test -race -count=1 ./...`
- [x] `go build -o webserver .`
- [x] `npm audit --audit-level=moderate`
- [x] `npm run test:e2e`

Live smoke:

- [x] disposable-host reachability and safety check completed
- [x] temp app DB and temp `known_hosts` used
- [x] setup/login completed
- [x] disposable host added, scanned, and trusted
- [x] update flow reached a terminal result
- [x] scheduled policy scan/run record verified
- [x] audit report, job report, dashboard/observability, and backup export verified
- [x] timeout regression guard verified

Smoke result:

- Runtime code under test: `a5e9c17`
- Phase 12 docs/status commit: `49f09c4`
- Disposable app DB path: `/tmp/slu-phase12-smoke.kw7zeX/servers.db`
- Disposable known-hosts path: `/tmp/slu-phase12-smoke.kw7zeX/known_hosts`
- Disposable target name: `release-smoke-target`
- Target OS: Ubuntu 25.04 on Linux `6.14.0-37-generic`
- Target reachability/safety check: SSH login succeeded; `/etc/os-release`, `uname -a`, and `apt-get -s upgrade` completed; simulated upgrade reported `0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded`.
- Update action result: `/api/update/release-smoke-target` created job `a2b32429276cd0d0e207666f9efab9b3` and finished `done` with `No packages to upgrade`.
- Scheduled policy result: scan-only policy run `1` created job `3c8a5b5d2aa6321a6532d981723fad0e` and finished `succeeded` with `Scheduled scan completed: no pending updates`.
- Audit/report result: audit report `/api/reports/audit/10`, update job report, scheduled scan job report, dashboard summary, and observability `24h` summary loaded successfully.
- Backup export result: `/api/backup/export` returned `simplelinuxupdater-backup-20260520T022918Z.slubkp`, 10142 bytes, with job `6c519e51c25fe3c5d11ddfdf22296acd`.
- Timeout regression guard: restart with `DEBIAN_UPDATER_SSH_COMMAND_TIMEOUT_SECONDS=1` and `DEBIAN_UPDATER_RETRY_MAX_ATTEMPTS=1`; update job `d5b0a3837e6e430d1ac9711a3181479b` finished `error` with `command timed out after 1s`.
- Skipped steps and exact reasons: pending approval approve/cancel was not exercised because both the read-only precheck and live update found no pending packages, so the update completed directly without entering `pending_approval`.

## Final Runtime State

- No `//lint:ignore U1000` compatibility wrappers remain.
- Default router dependencies now create fresh app-scoped service, broker, barrier, rate-limiter, server-state, metrics-token, policy, update, backup, audit, and observability instances instead of reusing mutable service singletons.
- `package main` remains the process startup and route-adapter layer. It owns DB path/opening, encryption-key file loading, environment-driven process config, route registration, and command startup.
- Remaining package-level values are process startup state, constants, pure helper functions, compiled regexes, and low-level test hooks that require process-wide replacement.

## Phase 0 Contract Coverage

- Route inventory remains covered by `criticalRouteInventory`.
- Backend contract tests cover auth/middleware behavior, representative route groups, server list shape, auth/session shape, backup status/export shape, audit/job reports, policy list/create/settings/runs shape, and update approve/cancel route contracts.
