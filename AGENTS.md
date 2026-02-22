# AGENTS.md - SimpleLinuxUpdater

This file provides guidance for agentic coding agents working on this codebase.

## Project Overview

- **Language**: Go 1.25+
- **Web Framework**: Gin
- **Database**: SQLite (modernc.org/sqlite)
- **SSH**: golang.org/x/crypto/ssh

## Build Commands

```bash
# Build the webserver binary
go build -o webserver webserver.go

# Run the application
./webserver

# Cross-compile for Linux amd64 (from Windows)
set GOOS=linux
set GOARCH=amd64
go build -o webserver webserver.go
```

## Test Commands

```bash
# Run all tests
go test ./...

# Run all tests with verbose output
go test -v ./...

# Run all tests with race detector
go test -race -count=1 ./...

# Run tests with coverage
go test -covermode=atomic -coverprofile=coverage.out ./...

# Show coverage summary
go tool cover -func=coverage.out | tail -n 1

# Run a single test file
go test -v -run TestName file_test.go

# Run a single test function
go test -v -run TestNormalizePort

# Run tests matching a pattern
go test -v -run "Test.*Port"

# Run post-update health check tests
go test -v -run "TestRunPostUpdateHealthChecks|TestRunUpdateWithActorPostcheck"
```

## Code Style Guidelines

### General

- Use `gofmt` for formatting (automatic with Go)
- Run `go vet` before committing: `go vet ./...`
- Ensure code compiles: `go build ./...`

### Imports

- Group imports: standard library first, then third-party
- Use blank line between groups
- Example:
```go
import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "strings"
    "sync"
    "time"

    "github.com/gin-gonic/gin"
    "golang.org/x/crypto/ssh"
    _ "modernc.org/sqlite"
)
```

### Naming Conventions

- **Variables/Functions**: camelCase (e.g., `serverName`, `normalizePort`)
- **Constants**: PascalCase or camelCase with prefix (e.g., `const maxUploadSize = 64 * 1024`)
- **Types/Structs**: PascalCase (e.g., `Server`, `ServerStatus`)
- **Package**: lowercase, short (e.g., `main`)
- **JSON fields**: PascalCase with JSON tags for exact mapping
- **Acronyms**: Keep as originally cased (e.g., `URL`, `ID`, `SSH` not `Url`, `Id`, `Ssh`)

### Types and Structs

- Use explicit types rather than `interface{}`
- Use structs with tags for serialization
- Example:
```go
type Server struct {
    Name string   `json:"name"`
    Host string   `json:"host"`
    Port int      `json:"port"`
    User string   `json:"user"`
    Pass string   `json:"pass"`
    Key  string   `json:"-"`
    Tags []string `json:"tags"`
}
```

### Error Handling

- Return errors rather than using global error variables where possible
- Use sentinel errors for expected error conditions:
```go
var errActionInProgress = errors.New("action already in progress")
```
- Use `fmt.Errorf` with %w for wrapping errors
- Check errors immediately after calls
- Use `errors.Is` and `errors.As` for error checking

### Concurrency

- Use `sync.Mutex` for protecting shared state
- Use `sync.RWMutex` for read-heavy scenarios
- Use `sync.Once` for one-time initialization
- Always use `defer` to unlock mutexes
- Example:
```go
mu.Lock()
defer mu.Unlock()
// protected code
```

### Database

- Use prepared statements for parameterized queries
- Handle `sql.ErrNoRows` appropriately
- Close resources with `defer`

### SSH Connections

- Use interfaces for testability:
```go
type sshConnection interface {
    NewSession() (sshSessionRunner, error)
    Close() error
}
```
- Inject connection functions for mocking in tests
- Set connection timeouts: `sshConnectTimeout = 15 * time.Second`

### HTTP Handlers (Gin)

- Use Gin context methods (`c.JSON`, `c.Bind`, etc.)
- Return appropriate HTTP status codes
- Log errors appropriately

### Security

- Never log secrets, passwords, or SSH keys
- Encrypt sensitive data at rest (passwords, SSH keys)
- Use constant-time comparison for secrets (`crypto/subtle`)
- Validate all user inputs
- Use parameterized queries for database operations

### Testing

- Use table-driven tests where appropriate
- Test both success and failure cases
- Use `t.Run` for sub-tests
- Use descriptive test names
- Cover both blocking and warning-only behavior for health checks
- When update flow behavior changes, include at least one end-to-end runner test with audit metadata assertions
- Example:
```go
func TestNormalizePort(t *testing.T) {
    tests := []struct {
        name string
        in   int
        want int
    }{
        {"zero defaults to 22", 0, 22},
        {"negative defaults to 22", -5, 22},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := normalizePort(tt.in); got != tt.want {
                t.Fatalf("normalizePort(%d) = %d, want %d", tt.in, got, tt.want)
            }
        })
    }
}
```

### Configuration

- Use environment variables for configuration
- Validate required environment variables at startup
- Provide sensible defaults
- Document all environment variables in README

### Logging

- Use standard `log` package
- Log errors with context
- Never log sensitive information

### Frontend UI Consistency

- Use the visual style from `templates/observability.html` as the default design baseline for all pages.
- Keep the same core theme tokens (`--bg`, `--card`, `--card-alt`, `--text`, `--subtle`, `--accent`, `--border`, `--shadow`) unless there is an explicit product decision to change them.
- Reuse the same component language for `hero`, `card`, nav links, buttons, inputs, selects, table styling, and hover states to maintain a consistent experience.
- For UI updates in `templates/index.html` and `templates/manage.html`, prefer aligning to Observability styling rather than introducing a new visual direction.
- Preserve responsiveness behavior across desktop and mobile when applying style changes.

## CI/CD

The project uses GitHub Actions (see `.github/workflows/ci.yml`):
- Runs unit tests, race detector tests, and coverage tests on pushes/PRs to main
- Go version: 1.25.x
- No separate lint step (Go's built-in tooling is used)

## Release Process

- Tags matching `v*` trigger release workflow
- Ensure tests pass before tagging
- Update version in README.md and templates/index.html
- Add changelog entry in CHANGELOG.md
