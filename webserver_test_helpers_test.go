package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	internalbackup "debian-updater/internal/backup"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

type testApp struct {
	Router         *gin.Engine
	Handler        http.Handler
	DBPath         string
	KnownHostsPath string
	Deps           AppDeps
}

type testAppOptions struct {
	DBPath string
	Deps   AppDeps
}

func setDialSSHConnection(fn func(Server, *ssh.ClientConfig) (sshConnection, error)) {
	dialSSHConnectionMu.Lock()
	defer dialSSHConnectionMu.Unlock()
	dialSSHConnection = fn
}

func newIsolatedTestApp(t *testing.T) *testApp {
	t.Helper()
	preserveServerState(t)
	func() {
		mu.Lock()
		defer mu.Unlock()
		servers = nil
		statusMap = map[string]*ServerStatus{}
	}()
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", "")
	return newTestApp(t, testAppOptions{DBPath: filepath.Join(t.TempDir(), "app.db")})
}

func newTestAppWithDeps(t *testing.T, dbFile string, deps AppDeps) *testApp {
	t.Helper()
	return newTestApp(t, testAppOptions{DBPath: dbFile, Deps: deps})
}

func newTestApp(t *testing.T, opts testAppOptions) *testApp {
	t.Helper()
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveEncryptionState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	resetMissedUpdatePolicyTicksForTest()
	t.Cleanup(resetMissedUpdatePolicyTicksForTest)

	dbFile := strings.TrimSpace(opts.DBPath)
	if dbFile == "" {
		dbFile = filepath.Join(t.TempDir(), "app.db")
	}
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)
	if opts.Deps.DBPath == nil {
		opts.Deps.DBPath = func() string {
			return dbFile
		}
	}
	if opts.Deps.DB == nil {
		appDB, err := sql.Open("sqlite", dbFile)
		if err != nil {
			t.Fatalf("open test app db: %v", err)
		}
		appDB.SetMaxOpenConns(1)
		appDB.SetMaxIdleConns(1)
		if _, err := appDB.Exec(fmt.Sprintf("PRAGMA busy_timeout=%d", sqliteBusyTimeoutMS)); err != nil {
			_ = appDB.Close()
			t.Fatalf("set test app db busy_timeout: %v", err)
		}
		if _, err := appDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
			_ = appDB.Close()
			t.Fatalf("set test app db journal_mode: %v", err)
		}
		if _, err := appDB.Exec("PRAGMA synchronous=NORMAL"); err != nil {
			_ = appDB.Close()
			t.Fatalf("set test app db synchronous mode: %v", err)
		}
		if err := ensureSchema(appDB); err != nil {
			_ = appDB.Close()
			t.Fatalf("migrate test app db schema: %v", err)
		}
		t.Cleanup(func() {
			_ = appDB.Close()
		})
		opts.Deps.DB = func() *sql.DB {
			return appDB
		}
	}
	if opts.Deps.BackupBarrier == nil {
		opts.Deps.BackupBarrier = internalbackup.NewBarrier()
	}
	if opts.Deps.LoginRateLimiter == nil {
		opts.Deps.LoginRateLimiter = NewAuthRateLimiter(authRateLimitWindow, authLoginRateLimitMaxAttempts)
		t.Cleanup(opts.Deps.LoginRateLimiter.Stop)
	}
	if opts.Deps.PasswordChangeRateLimiter == nil {
		opts.Deps.PasswordChangeRateLimiter = NewAuthRateLimiter(authRateLimitWindow, authPasswordChangeMaxAttempts)
		t.Cleanup(opts.Deps.PasswordChangeRateLimiter.Stop)
	}
	if opts.Deps.SetupRateLimiter == nil {
		opts.Deps.SetupRateLimiter = NewAuthRateLimiter(authRateLimitWindow, authSetupRateLimitMaxAttempts)
		t.Cleanup(opts.Deps.SetupRateLimiter.Stop)
	}
	if opts.Deps.MetricsRateLimiter == nil {
		opts.Deps.MetricsRateLimiter = NewAuthRateLimiter(metricsRateLimitWindow, metricsRateLimitMaxAttempts)
		t.Cleanup(opts.Deps.MetricsRateLimiter.Stop)
	}

	knownHostsPath := strings.TrimSpace(os.Getenv("DEBIAN_UPDATER_KNOWN_HOSTS"))
	if knownHostsPath == "" {
		knownHostsPath = filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
			t.Fatalf("write test known_hosts: %v", err)
		}
		t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)
	}

	deps := opts.Deps.withDefaults()
	router, err := setupRouterWithDeps(deps)
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
	sm := currentSessionManager()
	if sm == nil {
		t.Fatalf("setupRouterWithDeps() did not initialize a session manager")
	}
	return &testApp{
		Router:         router,
		Handler:        sm.LoadAndSave(router),
		DBPath:         dbFile,
		KnownHostsPath: knownHostsPath,
		Deps:           deps,
	}
}

func (app *testApp) authenticate(t *testing.T) *http.Cookie {
	t.Helper()
	setupBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
	setupRec := httptest.NewRecorder()
	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", setupBody)
	markSameOriginAuthRequest(setupReq)
	setupReq.Header.Set("Content-Type", "application/json")
	app.Handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", setupRec.Code, http.StatusOK, setupRec.Body.String())
	}
	return testSessionCookieFromRecorder(t, setupRec)
}
