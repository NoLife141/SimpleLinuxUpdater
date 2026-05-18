package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	return newTestAppWithDB(t, filepath.Join(t.TempDir(), "app.db"))
}

func newTestAppWithDB(t *testing.T, dbFile string) *testApp {
	t.Helper()
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	resetMissedUpdatePolicyTicksForTest()
	t.Cleanup(resetMissedUpdatePolicyTicksForTest)

	if strings.TrimSpace(dbFile) == "" {
		dbFile = filepath.Join(t.TempDir(), "app.db")
	}
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)

	knownHostsPath := strings.TrimSpace(os.Getenv("DEBIAN_UPDATER_KNOWN_HOSTS"))
	if knownHostsPath == "" {
		knownHostsPath = filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
			t.Fatalf("write test known_hosts: %v", err)
		}
		t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)
	}

	deps := NewDefaultAppDeps()
	router, err := setupRouterWithDeps(deps)
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
	return &testApp{
		Router:         router,
		Handler:        sessionManager.LoadAndSave(router),
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
