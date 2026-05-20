[README](../README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Usage](usage.md) | [Deployment](deployment.md) | [Security](security.md) | [Troubleshooting](troubleshooting.md) | [Architecture](architecture.md) | [Contributing](contributing.md)

# Contributing

## Table of contents

- [Who we need](#who-we-need)
- [How to help](#how-to-help)
- [If you want to code](#if-you-want-to-code)
- [Backend conventions](#backend-conventions)
- [Testing pattern](#testing-pattern)
- [Implementation examples](#implementation-examples)
- [Build and test](#build-and-test)

## Who we need

If you run Linux servers (Debian/Ubuntu) or a homelab, your feedback is the most valuable input for this project. The goal is to make updates safer and more predictable in real environments.

Examples of useful contributors:

- Homelab users running a few machines and willing to test upgrades.
- Linux admins managing multiple hosts and able to share operational expectations.
- Anyone who can provide clear bug reports and reproduction steps.

## How to help

You do not need to write code to contribute.

High-impact contributions:

- File bug reports with:
  - your OS, for both updater host and target host;
  - what you clicked or what command you ran;
  - relevant server logs from the UI.
- Suggest features or defaults, such as health-check blocking policies, retry behavior, or approval workflow.
- Share what you want to see in observability, especially which metrics and failure causes are useful.
- Improve docs for clarity, missing steps, or safer deployment guidance.

## If you want to code

If you want to implement a fix or feature:

- Open an issue first, or comment on an existing one, describing the change.
- Keep changes focused and add tests when behavior changes.
- Preserve route paths, JSON fields, schemas, middleware behavior, audit event names, job strings, template paths, and static asset paths unless the change explicitly requires a migration.
- Submit changes via a pull request.

## Backend conventions

- `setupRouter()` is the production entrypoint and delegates to `setupRouterWithDeps(NewDefaultAppDeps())`.
- `setupRouterWithDeps(AppDeps)` owns Gin engine creation, trusted proxies, middleware, maintenance/job/session initialization, templates, static files, and route registration.
- `registerRoutes(router, deps)` is the route wiring entrypoint. Public routes must stay before `authGateMiddleware`; protected write routes must stay behind `sameOriginWriteMiddleware`.
- Use the owning internal package when adding domain behavior:
  - `internal/audit` for audit persistence, listing, pruning, and Markdown reports.
  - `internal/auth` for users, sessions, same-origin helpers, and rate limiters.
  - `internal/backup` for backup archive/export/restore behavior and restore barriers.
  - `internal/servers` for inventory state, persistence, credentials, known_hosts, and SSH auth helpers.
  - `internal/policies` for scheduled policy validation, matching, run records, scheduler ticks, and missed-run replay.
  - `internal/updates` for update/autoremove/sudoers execution, approval/cancel, CVE enrichment, SSH retries, and scheduled scans.
  - `internal/observability` for dashboard summaries, observability summaries, Prometheus rendering, and metrics tokens.
  - `internal/events` and `internal/jobs` for dashboard SSE fan-out and persisted job management.
- Use `AppDeps` to inject DB providers, services, runtime state, job managers, session managers, event brokers, rate limiters, and time providers. Do not add mutable package-level service singletons.
- Do not put new business logic directly in route registration. Route handlers should parse requests, preserve response behavior, and delegate.

## Testing pattern

Use service tests when the behavior can be tested without Gin. Use HTTP tests when the important behavior is routing, auth, CSRF, status codes, or JSON shape.

Preferred app fixtures:

- `newIsolatedTestApp(t)` for a fully isolated router with temp DB, temp `known_hosts`, fresh session state, fresh job manager, reset rate limiters, reset metrics token state, and empty in-memory server/status state.
- `newTestAppWithDeps(t, dbFile, deps)` when a route must use injected services or callbacks.
- `app.authenticate(t)` to create the admin account and return an authenticated session cookie.

Fixture rules:

- Prefer `newIsolatedTestApp(t)` for HTTP contract coverage so tests do not share DB rows, sessions, jobs, auth rate limits, server state, backup barriers, dashboard brokers, metrics-token caches, SSH/known_hosts hooks, or maintenance state.
- Prefer package-level service/repository tests for validation, matching, persistence, parsing, retry, and report rendering logic that does not require Gin middleware.
- Use `newTestAppWithDeps` only when the behavior under test needs an injected service, fake callback, fixed time provider, custom job manager, or custom DB provider.
- Keep route tests focused on auth, same-origin behavior, status codes, JSON keys, headers, downloads, and route inventory.

Example route test shape:

```go
app := newIsolatedTestApp(t)
cookie := app.authenticate(t)

req := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
req.AddCookie(cookie)
rec := httptest.NewRecorder()
app.Handler.ServeHTTP(rec, req)
```

Example injected service shape:

```go
app := newTestAppWithDeps(t, filepath.Join(t.TempDir(), "app.db"), AppDeps{
    PolicyService: NewPolicyService(PolicyServiceDeps{
        ListPolicies: func() ([]UpdatePolicy, error) {
            return []UpdatePolicy{policy}, nil
        },
        SnapshotServers: func() []Server {
            return []Server{{Name: "srv-prod", Tags: []string{"prod"}}}
        },
    }),
})
```

## Implementation examples

### Add a protected API route

1. Add the route in the smallest matching route group in `registerRoutes`.
2. If the handler needs a dependency, pass `AppDeps` into the group and call a `handle...WithDeps` helper.
3. Keep the existing middleware order: public routes first, then `authGateMiddleware`, then `sameOriginWriteMiddleware`.
4. Put behavior in the owning internal service or repository unless the route only composes existing behavior.
5. Add the critical method/path pair to the route inventory test when the endpoint is user-facing or relied on by the UI.
6. Add an HTTP test with `newIsolatedTestApp` or `newTestAppWithDeps` for auth, status code, and JSON shape.

### Add a new audit event

1. Use the app's injected audit service from route dependencies, or the `internal/audit.Service` directly in package-level tests.
2. Use stable action names such as `feature.action` and keep metadata JSON small, sanitized, and free of secrets.
3. Record failures and successes close to the operation that actually succeeded or failed.
4. Do not change `AuditEvent` JSON fields, report routes, or existing report formatting unless the change includes compatibility tests.
5. Add service or route tests that assert the action, status, target, and important metadata keys.

### Add a scheduled-policy rule

1. Add matching or validation behavior in `internal/policies.Service`, not directly in route handlers.
2. Preserve existing targeting inputs: `target_tag`, `include_tags`, `exclude_tags`, `target_servers`, and per-server overrides.
3. Preserve run-record behavior: skipped, superseded, blackout, maintenance, missing-server, no-match, and busy reasons should remain explicit.
4. Keep due-slot calculations in the app timezone.
5. Add table-driven service tests for matching/validation and at least one route or scheduler test when the API response changes.

## Build and test

Build:

```bash
go build -o webserver .
```

Run tests:

```bash
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./...
npm run test:e2e
```

Optional hardening checks when tools are available:

```bash
staticcheck ./...
govulncheck ./...
actionlint
npm audit --audit-level=moderate
```
