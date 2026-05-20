package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	internalbackup "debian-updater/internal/backup"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
)

func TestSetupRouterWithDepsUsesInjectedInitialization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	dbFile := filepath.Join(t.TempDir(), "deps-init.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)

	db := getDB()
	jm := newJobManager(db)
	maintenanceCalled := false
	trustedProxiesCalled := false

	router, err := setupRouterWithDeps(AppDeps{
		DB:         func() *sql.DB { return db },
		JobManager: jm,
		TrustedProxies: func() []string {
			trustedProxiesCalled = true
			return nil
		},
		InitializeMaintenanceState: func() error {
			maintenanceCalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
	if router == nil {
		t.Fatalf("setupRouterWithDeps() returned nil router")
	}
	if !trustedProxiesCalled {
		t.Fatalf("trusted proxy provider was not called")
	}
	if !maintenanceCalled {
		t.Fatalf("maintenance initializer was not called")
	}
	if got := currentJobManager(); got != jm {
		t.Fatalf("current job manager = %p, want injected %p", got, jm)
	}
	if sessionManager == nil {
		t.Fatalf("session manager was not initialized")
	}
}

func TestIsolatedTestAppSeparatesDBAndJobManager(t *testing.T) {
	appOne := newIsolatedTestApp(t)
	jmOne := currentJobManager()
	appOneCookie := appOne.authenticate(t)

	appTwo := newIsolatedTestApp(t)
	jmTwo := currentJobManager()
	appTwoCookie := appTwo.authenticate(t)

	if jmOne == nil || jmTwo == nil {
		t.Fatalf("test app job managers must be initialized")
	}
	if jmOne == jmTwo {
		t.Fatalf("test apps share job manager %p", jmOne)
	}
	if got := appOne.Deps.CurrentJobManager(); got != jmOne {
		t.Fatalf("first app current job manager changed after second app initialized: got %p want %p", got, jmOne)
	}
	if got := appTwo.Deps.CurrentJobManager(); got != jmTwo {
		t.Fatalf("second app current job manager = %p, want %p", got, jmTwo)
	}
	if appOne.DBPath == appTwo.DBPath {
		t.Fatalf("test apps share db path %q", appOne.DBPath)
	}
	if appOne.KnownHostsPath == appTwo.KnownHostsPath {
		t.Fatalf("test apps share known_hosts path %q", appOne.KnownHostsPath)
	}
	if !authUserExistsInDB(t, appOne.DBPath) {
		t.Fatalf("first app auth user was not written to first db")
	}
	if !authUserExistsInDB(t, appTwo.DBPath) {
		t.Fatalf("second app auth user was not written to second db")
	}
	if appOneCookie.Value == appTwoCookie.Value {
		t.Fatalf("test apps reused the same session cookie value")
	}
}

func TestIsolatedTestAppSessionLookupStaysAppScoped(t *testing.T) {
	appOne := newIsolatedTestApp(t)
	appOneCookie := appOne.authenticate(t)
	appTwo := newIsolatedTestApp(t)
	_ = appTwo.authenticate(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.AddCookie(appOneCookie)
	appOne.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first app auth status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp struct {
		Authenticated bool   `json:"authenticated"`
		Username      string `json:"username"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal auth status: %v", err)
	}
	if !resp.Authenticated || resp.Username != "admin" {
		t.Fatalf("first app auth status = %+v, want authenticated admin after second app initialized", resp)
	}
}

func TestIsolatedTestAppSeparatesAuthRateLimiters(t *testing.T) {
	appOneLimiter := NewAuthRateLimiter(authRateLimitWindow, 1)
	t.Cleanup(appOneLimiter.Stop)
	appTwoLimiter := NewAuthRateLimiter(authRateLimitWindow, 5)
	t.Cleanup(appTwoLimiter.Stop)

	appOne := newTestAppWithDeps(t, filepath.Join(t.TempDir(), "auth-rate-one.db"), AppDeps{
		SetupRateLimiter: appOneLimiter,
	})
	appTwo := newTestAppWithDeps(t, filepath.Join(t.TempDir(), "auth-rate-two.db"), AppDeps{
		SetupRateLimiter: appTwoLimiter,
	})

	firstOne := performInvalidSetupRequest(appOne.Handler)
	if firstOne.Code != http.StatusBadRequest {
		t.Fatalf("first app first setup status = %d, want %d (body=%s)", firstOne.Code, http.StatusBadRequest, firstOne.Body.String())
	}
	secondOne := performInvalidSetupRequest(appOne.Handler)
	if secondOne.Code != http.StatusTooManyRequests {
		t.Fatalf("first app second setup status = %d, want %d (body=%s)", secondOne.Code, http.StatusTooManyRequests, secondOne.Body.String())
	}
	firstTwo := performInvalidSetupRequest(appTwo.Handler)
	if firstTwo.Code != http.StatusBadRequest {
		t.Fatalf("second app first setup status = %d, want %d (body=%s)", firstTwo.Code, http.StatusBadRequest, firstTwo.Body.String())
	}
}

func TestSetupRouterWithDepsDefaultsAuthServiceToInjectedDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	globalDBPath := filepath.Join(t.TempDir(), "global-auth.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", globalDBPath)
	_ = getDB()

	routeDBPath := filepath.Join(t.TempDir(), "route-auth.db")
	routeDB, err := sql.Open("sqlite", routeDBPath)
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	if err := prepareInjectedAppDB(routeDB); err != nil {
		t.Fatalf("prepare injected db: %v", err)
	}

	router, err := setupRouterWithDeps(AppDeps{
		DB: func() *sql.DB { return routeDB },
	})
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(router)

	setupRec := httptest.NewRecorder()
	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"username":"admin","password":"StrongPass123"}`))
	markSameOriginAuthRequest(setupReq)
	setupReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", setupRec.Code, http.StatusOK, setupRec.Body.String())
	}
	if !authUserExistsInDB(t, routeDBPath) {
		t.Fatalf("auth setup did not write to injected db")
	}
	if authUserExistsInDB(t, globalDBPath) {
		t.Fatalf("auth setup wrote to global db instead of only injected db")
	}
}

func TestSetupRouterWithDepsDefaultsServerInventoryToInjectedDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	globalDBPath := filepath.Join(t.TempDir(), "global-inventory.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", globalDBPath)
	_ = getDB()

	routeDBPath := filepath.Join(t.TempDir(), "route-inventory.db")
	routeDB, err := sql.Open("sqlite", routeDBPath)
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	if err := prepareInjectedAppDB(routeDB); err != nil {
		t.Fatalf("prepare injected db: %v", err)
	}

	router, err := setupRouterWithDeps(AppDeps{
		DB: func() *sql.DB { return routeDB },
	})
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(router)

	setupRec := httptest.NewRecorder()
	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"username":"admin","password":"StrongPass123"}`))
	markSameOriginAuthRequest(setupReq)
	setupReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", setupRec.Code, http.StatusOK, setupRec.Body.String())
	}
	sessionCookie := testSessionCookieFromRecorder(t, setupRec)

	serverRec := httptest.NewRecorder()
	serverReq := httptest.NewRequest(http.MethodPost, "/api/servers", strings.NewReader(`{"name":"srv-injected-db","host":"192.0.2.10","user":"root","pass":"pw"}`))
	serverReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(serverReq)
	serverReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(serverRec, serverReq)
	if serverRec.Code != http.StatusCreated {
		t.Fatalf("server create status = %d, want %d (body=%s)", serverRec.Code, http.StatusCreated, serverRec.Body.String())
	}
	if !serverExistsInDB(t, routeDBPath, "srv-injected-db") {
		t.Fatalf("server create did not write to injected db")
	}
	if serverExistsInDB(t, globalDBPath, "srv-injected-db") {
		t.Fatalf("server create wrote to global db instead of only injected db")
	}
}

func TestAppScopedServerInventoryImportsLegacyServers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveServerState(t)
	preserveEncryptionState(t)

	legacyDir := t.TempDir()
	t.Chdir(legacyDir)
	legacyServers := []Server{{
		Name: "legacy-app",
		Host: "192.0.2.44",
		Port: 22,
		User: "root",
		Pass: "pw",
		Tags: []string{"legacy"},
	}}
	payload, err := json.Marshal(legacyServers)
	if err != nil {
		t.Fatalf("marshal legacy servers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, legacyServersFileName), payload, 0600); err != nil {
		t.Fatalf("write legacy servers file: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "legacy-import.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy import db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := prepareInjectedAppDB(db); err != nil {
		t.Fatalf("prepare legacy import db: %v", err)
	}
	state := newServerState()
	service := newServerInventoryServiceWithStateDBPath(state, func() *sql.DB { return db }, func() string { return dbPath })
	service.Load()
	initializeServerStateStatuses(state)

	statuses := service.ListStatuses()
	if len(statuses) != 1 || statuses[0].Name != "legacy-app" {
		t.Fatalf("app-scoped statuses after legacy import = %+v, want legacy-app", statuses)
	}
	if !serverExistsInDB(t, dbPath, "legacy-app") {
		t.Fatalf("legacy server was not persisted to app-scoped db")
	}
}

func TestSetupRouterWithDepsDefaultsGlobalKeyToInjectedDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	preserveEncryptionState(t)
	globalDBPath := filepath.Join(t.TempDir(), "global-key-global.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", globalDBPath)
	_ = getDB()

	routeDBPath := filepath.Join(t.TempDir(), "global-key-route.db")
	routeDB, err := sql.Open("sqlite", routeDBPath)
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	if err := prepareInjectedAppDB(routeDB); err != nil {
		t.Fatalf("prepare injected db: %v", err)
	}

	router, err := setupRouterWithDeps(AppDeps{
		DB:     func() *sql.DB { return routeDB },
		DBPath: func() string { return routeDBPath },
	})
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(router)

	setupRec := httptest.NewRecorder()
	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"username":"admin","password":"StrongPass123"}`))
	markSameOriginAuthRequest(setupReq)
	setupReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", setupRec.Code, http.StatusOK, setupRec.Body.String())
	}
	sessionCookie := testSessionCookieFromRecorder(t, setupRec)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("key", "id_ed25519")
	if err != nil {
		t.Fatalf("CreateFormFile() unexpected error: %v", err)
	}
	if _, err := part.Write([]byte(testPrivateKeyPEM(t))); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	uploadRec := httptest.NewRecorder()
	uploadReq := httptest.NewRequest(http.MethodPost, "/api/keys/global", &body)
	uploadReq.AddCookie(sessionCookie)
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())
	markSameOriginAuthRequest(uploadReq)
	handler.ServeHTTP(uploadRec, uploadReq)
	if uploadRec.Code != http.StatusOK {
		t.Fatalf("global key upload status = %d, want %d (body=%s)", uploadRec.Code, http.StatusOK, uploadRec.Body.String())
	}

	statusRec := httptest.NewRecorder()
	statusReq := httptest.NewRequest(http.MethodGet, "/api/keys/global", nil)
	statusReq.AddCookie(sessionCookie)
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("global key status = %d, want %d (body=%s)", statusRec.Code, http.StatusOK, statusRec.Body.String())
	}
	var statusResp struct {
		HasKey bool `json:"has_key"`
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("unmarshal global key status: %v", err)
	}
	if !statusResp.HasKey {
		t.Fatalf("global key status has_key = false, want true")
	}
	if !settingExistsInDB(t, routeDBPath, globalKeySetting) {
		t.Fatalf("global key route did not write to injected db")
	}
	if settingExistsInDB(t, globalDBPath, globalKeySetting) {
		t.Fatalf("global key route wrote to global db instead of only injected db")
	}
}

func TestAppGlobalKeyHasKeyReturnsDBErrors(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "global-key-error.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	_, _, _, hasKey := newAppGlobalKeyStore(func() *sql.DB { return db })
	ok, err := hasKey()
	if err == nil {
		t.Fatalf("HasGlobalKey() error = nil, want closed DB error")
	}
	if ok {
		t.Fatalf("HasGlobalKey() ok = true, want false on DB error")
	}
}

func TestSetupRouterWithDepsInitializesStatusesForPersistedServers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	preserveEncryptionState(t)

	globalDBPath := filepath.Join(t.TempDir(), "global-persisted-servers.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", globalDBPath)
	_ = getDB()

	routeDBPath := filepath.Join(t.TempDir(), "route-persisted-servers.db")
	routeDB, err := sql.Open("sqlite", routeDBPath)
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	if err := prepareInjectedAppDB(routeDB); err != nil {
		t.Fatalf("prepare injected db: %v", err)
	}

	seedState := newServerState()
	seedService := newServerInventoryServiceWithStateAndDB(seedState, func() *sql.DB { return routeDB })
	if _, err := seedService.Create(Server{
		Name: "persisted-server",
		Host: "192.0.2.55",
		Port: 22,
		User: "root",
		Pass: "pw",
		Tags: []string{"prod"},
	}); err != nil {
		t.Fatalf("seed persisted server: %v", err)
	}

	router, err := setupRouterWithDeps(AppDeps{
		DB:     func() *sql.DB { return routeDB },
		DBPath: func() string { return routeDBPath },
	})
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(router)

	setupRec := httptest.NewRecorder()
	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"username":"admin","password":"StrongPass123"}`))
	markSameOriginAuthRequest(setupReq)
	setupReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", setupRec.Code, http.StatusOK, setupRec.Body.String())
	}
	sessionCookie := testSessionCookieFromRecorder(t, setupRec)

	listRec := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	listReq.AddCookie(sessionCookie)
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("server list status = %d, want %d (body=%s)", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var statuses []ServerStatus
	if err := json.Unmarshal(listRec.Body.Bytes(), &statuses); err != nil {
		t.Fatalf("unmarshal server list: %v", err)
	}
	if len(statuses) != 1 || statuses[0].Name != "persisted-server" || statuses[0].Status != "idle" {
		t.Fatalf("server list statuses = %+v, want persisted idle server", statuses)
	}
}

func TestSetupRouterWithDepsDefaultsPolicyRepositoryToInjectedDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	globalDBPath := filepath.Join(t.TempDir(), "global-policy.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", globalDBPath)
	_ = getDB()

	routeDBPath := filepath.Join(t.TempDir(), "route-policy.db")
	routeDB, err := sql.Open("sqlite", routeDBPath)
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	if err := prepareInjectedAppDB(routeDB); err != nil {
		t.Fatalf("prepare injected db: %v", err)
	}

	router, err := setupRouterWithDeps(AppDeps{
		DB: func() *sql.DB { return routeDB },
	})
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(router)

	setupRec := httptest.NewRecorder()
	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"username":"admin","password":"StrongPass123"}`))
	markSameOriginAuthRequest(setupReq)
	setupReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", setupRec.Code, http.StatusOK, setupRec.Body.String())
	}
	sessionCookie := testSessionCookieFromRecorder(t, setupRec)

	policyBody := `{"name":"route policy","enabled":true,"target_servers":["srv-policy"],"package_scope":"security","execution_mode":"scan_only","cadence_kind":"daily","time_local":"02:30"}`
	policyRec := httptest.NewRecorder()
	policyReq := httptest.NewRequest(http.MethodPost, "/api/update-policies", strings.NewReader(policyBody))
	policyReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(policyReq)
	policyReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(policyRec, policyReq)
	if policyRec.Code != http.StatusCreated {
		t.Fatalf("policy create status = %d, want %d (body=%s)", policyRec.Code, http.StatusCreated, policyRec.Body.String())
	}
	if !policyExistsInDB(t, routeDBPath, "route policy") {
		t.Fatalf("policy create did not write to injected db")
	}
	if policyExistsInDB(t, globalDBPath, "route policy") {
		t.Fatalf("policy create wrote to global db instead of only injected db")
	}
}

func TestAppDepsDefaultPolicyServiceUsesAppScopedServerState(t *testing.T) {
	preserveServerState(t)
	mu.Lock()
	servers = nil
	statusMap = map[string]*ServerStatus{}
	mu.Unlock()

	routeDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "policy-server-state.db"))
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })

	state := newServerState()
	state.Lock()
	state.SetServers([]Server{{
		Name: "scoped-policy-server",
		Host: "192.0.2.60",
		Port: 22,
		User: "root",
		Tags: []string{"nightly"},
	}})
	state.SetStatusMap(map[string]*ServerStatus{
		"scoped-policy-server": {
			Name:   "scoped-policy-server",
			Status: "idle",
			Tags:   []string{"nightly"},
		},
	})
	state.Unlock()

	deps := AppDeps{
		DB:          func() *sql.DB { return routeDB },
		ServerState: state,
	}.withDefaults()
	policyDeps := deps.PolicyService.EnsureDeps()
	snapshot := policyDeps.SnapshotServers()
	if len(snapshot) != 1 || snapshot[0].Name != "scoped-policy-server" {
		t.Fatalf("policy server snapshot = %+v, want app-scoped server", snapshot)
	}
	if status := policyDeps.CurrentStatusSnapshot("scoped-policy-server"); status == nil || status.Status != "idle" {
		t.Fatalf("policy status snapshot = %+v, want app-scoped idle status", status)
	}
}

func TestAppDepsDefaultsBackupServiceToAppScopedInstance(t *testing.T) {
	routeDBPath := filepath.Join(t.TempDir(), "route-backup.db")
	routeDB, err := sql.Open("sqlite", routeDBPath)
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })

	deps := AppDeps{
		DB:     func() *sql.DB { return routeDB },
		DBPath: func() string { return routeDBPath },
	}.withDefaults()
	other := AppDeps{
		DB:     func() *sql.DB { return routeDB },
		DBPath: func() string { return routeDBPath },
	}.withDefaults()
	if deps.BackupService == nil {
		t.Fatalf("default backup service is nil")
	}
	if deps.BackupService == other.BackupService {
		t.Fatalf("default backup service reused mutable singleton %p", deps.BackupService)
	}
	if got := deps.BackupService.Status().DBPath; got != routeDBPath {
		t.Fatalf("backup status db path = %q, want injected path %q", got, routeDBPath)
	}
}

func TestBackupRoutesUseInjectedJobManager(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		body    func(t *testing.T) (*bytes.Buffer, string)
		wantErr string
	}{
		{
			name:   "export",
			method: http.MethodPost,
			path:   "/api/backup/export",
			body: func(t *testing.T) (*bytes.Buffer, string) {
				t.Helper()
				return bytes.NewBufferString(`{"passphrase":"very-strong-passphrase"}`), "application/json"
			},
			wantErr: "failed to create backup export job",
		},
		{
			name:   "restore",
			method: http.MethodPost,
			path:   "/api/backup/restore",
			body: func(t *testing.T) (*bytes.Buffer, string) {
				t.Helper()
				var body bytes.Buffer
				writer := multipart.NewWriter(&body)
				if err := writer.WriteField("passphrase", "very-strong-passphrase"); err != nil {
					t.Fatalf("write passphrase field: %v", err)
				}
				file, err := writer.CreateFormFile("file", "backup.slubkp")
				if err != nil {
					t.Fatalf("create backup form file: %v", err)
				}
				if _, err := file.Write([]byte("not-a-real-backup")); err != nil {
					t.Fatalf("write backup form file: %v", err)
				}
				if err := writer.Close(); err != nil {
					t.Fatalf("close multipart writer: %v", err)
				}
				return &body, writer.FormDataContentType()
			},
			wantErr: "failed to create backup restore job",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var scopedMu sync.RWMutex
			var scopedJobManager *JobManager
			jobDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), tc.name+"-jobs.db"))
			if err != nil {
				t.Fatalf("open job db: %v", err)
			}
			jobDB.SetMaxOpenConns(1)
			jobDB.SetMaxIdleConns(1)
			if err := ensureJobSchema(jobDB); err != nil {
				_ = jobDB.Close()
				t.Fatalf("ensure job schema: %v", err)
			}
			app := newTestAppWithDeps(t, filepath.Join(t.TempDir(), tc.name+"-app.db"), AppDeps{
				NewJobManager: func(*sql.DB) *JobManager {
					return newJobManagerWithNotify(jobDB, nil)
				},
				CurrentJobManager: func() *JobManager {
					scopedMu.RLock()
					defer scopedMu.RUnlock()
					return scopedJobManager
				},
				SetCurrentJobManager: func(jm *JobManager) {
					scopedMu.Lock()
					scopedJobManager = jm
					scopedMu.Unlock()
				},
			})
			cookie := app.authenticate(t)
			if err := jobDB.Close(); err != nil {
				t.Fatalf("close job db before backup request: %v", err)
			}

			body, contentType := tc.body(t)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.AddCookie(cookie)
			markSameOriginAuthRequest(req)
			req.Header.Set("Content-Type", contentType)
			app.Handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s status = %d, want %d (body=%s)", tc.name, rec.Code, http.StatusInternalServerError, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantErr) {
				t.Fatalf("%s body = %s, want error containing %q", tc.name, rec.Body.String(), tc.wantErr)
			}
		})
	}
}

func TestAppDepsDefaultObservabilityUsesAppScopedServerState(t *testing.T) {
	routeDBPath := filepath.Join(t.TempDir(), "observability-route.db")
	routeDB, err := sql.Open("sqlite", routeDBPath)
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	if err := ensureSchema(routeDB); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	state := newServerState()
	state.Lock()
	state.SetServers([]Server{{
		Name: "scoped-server",
		Host: "192.0.2.10",
		Port: 22,
		User: "root",
	}})
	state.SetStatusMap(map[string]*ServerStatus{
		"scoped-server": {
			Name:   "scoped-server",
			Status: "idle",
		},
	})
	state.Unlock()

	deps := AppDeps{
		DB:          func() *sql.DB { return routeDB },
		DBPath:      func() string { return routeDBPath },
		ServerState: state,
	}.withDefaults()
	summary, err := deps.ObservabilityService.BuildDashboardSummary("24h", time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildDashboardSummary() error = %v", err)
	}
	if len(summary.Servers) != 1 || summary.Servers[0].Name != "scoped-server" {
		t.Fatalf("dashboard servers = %+v, want app-scoped server", summary.Servers)
	}
}

func TestAppDepsDefaultsCreateFreshRuntimeState(t *testing.T) {
	routeDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "runtime-state.db"))
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	dbProvider := func() *sql.DB { return routeDB }
	if err := ensureJobSchema(routeDB); err != nil {
		t.Fatalf("ensure job schema: %v", err)
	}

	one := AppDeps{
		DB:                        dbProvider,
		BackupBarrier:             internalbackup.NewBarrier(),
		LoginRateLimiter:          NewAuthRateLimiter(authRateLimitWindow, authLoginRateLimitMaxAttempts),
		PasswordChangeRateLimiter: NewAuthRateLimiter(authRateLimitWindow, authPasswordChangeMaxAttempts),
		SetupRateLimiter:          NewAuthRateLimiter(authRateLimitWindow, authSetupRateLimitMaxAttempts),
		MetricsRateLimiter:        NewAuthRateLimiter(metricsRateLimitWindow, metricsRateLimitMaxAttempts),
	}.withDefaults()
	two := AppDeps{
		DB:                        dbProvider,
		BackupBarrier:             internalbackup.NewBarrier(),
		LoginRateLimiter:          NewAuthRateLimiter(authRateLimitWindow, authLoginRateLimitMaxAttempts),
		PasswordChangeRateLimiter: NewAuthRateLimiter(authRateLimitWindow, authPasswordChangeMaxAttempts),
		SetupRateLimiter:          NewAuthRateLimiter(authRateLimitWindow, authSetupRateLimitMaxAttempts),
		MetricsRateLimiter:        NewAuthRateLimiter(metricsRateLimitWindow, metricsRateLimitMaxAttempts),
	}.withDefaults()
	t.Cleanup(one.LoginRateLimiter.Stop)
	t.Cleanup(one.PasswordChangeRateLimiter.Stop)
	t.Cleanup(one.SetupRateLimiter.Stop)
	t.Cleanup(two.LoginRateLimiter.Stop)
	t.Cleanup(two.PasswordChangeRateLimiter.Stop)
	t.Cleanup(two.SetupRateLimiter.Stop)
	t.Cleanup(one.MetricsRateLimiter.Stop)
	t.Cleanup(two.MetricsRateLimiter.Stop)

	if err := one.initializeJobManager(); err != nil {
		t.Fatalf("initialize first job manager: %v", err)
	}
	if err := two.initializeJobManager(); err != nil {
		t.Fatalf("initialize second job manager: %v", err)
	}

	if one.AuthService == two.AuthService ||
		one.AuditService == two.AuditService ||
		one.BackupService == two.BackupService ||
		one.BackupBarrier == two.BackupBarrier ||
		one.ServerState == two.ServerState ||
		one.ServerInventoryService == two.ServerInventoryService ||
		one.PolicyService == two.PolicyService ||
		one.UpdateService == two.UpdateService ||
		one.ObservabilityService == two.ObservabilityService ||
		one.MetricsTokenService == two.MetricsTokenService ||
		one.DashboardEventBroker == two.DashboardEventBroker ||
		one.LoginRateLimiter == two.LoginRateLimiter ||
		one.PasswordChangeRateLimiter == two.PasswordChangeRateLimiter ||
		one.SetupRateLimiter == two.SetupRateLimiter ||
		one.MetricsRateLimiter == two.MetricsRateLimiter ||
		one.CurrentJobManager() == two.CurrentJobManager() {
		t.Fatalf("AppDeps defaults reused mutable runtime state")
	}
}

func TestAppDepsProductionDefaultsReuseLifecycleOwnedBarrierAndLimiters(t *testing.T) {
	deps := AppDeps{}.withDefaults()
	if deps.BackupBarrier != backupRestoreMu {
		t.Fatalf("default backup barrier = %p, want global lifecycle barrier %p", deps.BackupBarrier, backupRestoreMu)
	}
	if deps.LoginRateLimiter != loginRateLimiter ||
		deps.PasswordChangeRateLimiter != passwordChangeRateLimiter ||
		deps.SetupRateLimiter != setupRateLimiter ||
		deps.MetricsRateLimiter != metricsRateLimiter {
		t.Fatalf("default rate limiters should reuse lifecycle-owned package limiters")
	}
}

func TestAppDepsDefaultJobManagerSyncsAppScopedServerState(t *testing.T) {
	preserveServerState(t)
	routeDBPath := filepath.Join(t.TempDir(), "route-job-sync.db")
	routeDB, err := sql.Open("sqlite", routeDBPath)
	if err != nil {
		t.Fatalf("open route db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	if err := ensureSchema(routeDB); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	state := newServerState()
	server := Server{Name: "srv-job-sync", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	state.Lock()
	state.SetServers([]Server{server})
	state.SetStatusMap(map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle"},
	})
	state.Unlock()
	func() {
		mu.Lock()
		defer mu.Unlock()
		servers = []Server{server}
		statusMap = map[string]*ServerStatus{
			server.Name: {Name: server.Name, Status: "global-idle"},
		}
	}()

	deps := AppDeps{
		DB:          func() *sql.DB { return routeDB },
		DBPath:      func() string { return routeDBPath },
		ServerState: state,
	}.withDefaults()
	if err := deps.initializeJobManager(); err != nil {
		t.Fatalf("initialize job manager: %v", err)
	}
	job, err := deps.CurrentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: server.Name,
		Actor:      "admin",
		Status:     jobStatusQueued,
	})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	phase := jobPhaseAptUpdate
	status := jobStatusRunning
	if err := deps.CurrentJobManager().UpdateJob(job.ID, JobUpdate{Status: &status, Phase: &phase}); err != nil {
		t.Fatalf("update job: %v", err)
	}

	if got := state.CurrentStatusSnapshot(server.Name); got == nil || got.Status != "updating" {
		t.Fatalf("app-scoped status = %+v, want updating", got)
	}
	if got := currentStatusSnapshot(server.Name); got == nil || got.Status != "global-idle" {
		t.Fatalf("global status changed to %+v, want global-idle", got)
	}
}

func TestMetricsRouteUsesAppScopedRateLimiter(t *testing.T) {
	appLimiter := NewAuthRateLimiter(metricsRateLimitWindow, 5)
	t.Cleanup(appLimiter.Stop)
	globalLimiter := NewAuthRateLimiter(metricsRateLimitWindow, 1)
	prevGlobalLimiter := metricsRateLimiter
	metricsRateLimiter = globalLimiter
	t.Cleanup(func() {
		globalLimiter.Stop()
		metricsRateLimiter = prevGlobalLimiter
	})

	app := newTestAppWithDeps(t, filepath.Join(t.TempDir(), "metrics-route-limiter.db"), AppDeps{
		MetricsRateLimiter: appLimiter,
	})
	token, err := app.Deps.MetricsTokenService.Rotate()
	if err != nil {
		t.Fatalf("rotate metrics token: %v", err)
	}

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		app.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("metrics request %d status = %d, want %d (body=%s)", i+1, rec.Code, http.StatusOK, rec.Body.String())
		}
	}
}

func TestServerFactsRefreshRouteUsesInjectedDB(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	globalDBPath := filepath.Join(t.TempDir(), "global-facts.db")
	routeDBPath := filepath.Join(t.TempDir(), "route-facts.db")
	routeDB, err := sql.Open("sqlite", routeDBPath)
	if err != nil {
		t.Fatalf("open route db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	if err := ensureSchema(routeDB); err != nil {
		t.Fatalf("ensure route schema: %v", err)
	}
	origDial := getDialSSHConnection()
	setDialSSHConnection(func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		return &scriptedSSHConnection{
			responses: map[string]scriptedResponse{
				serverFactsOSCmd:     {stdout: "Ubuntu 24.04 LTS\n"},
				serverFactsUptimeCmd: {stdout: "12345.67 100.00\n"},
			},
		}, nil
	})
	t.Cleanup(func() {
		setDialSSHConnection(origDial)
	})
	app := newTestAppWithDeps(t, globalDBPath, AppDeps{
		DB:     func() *sql.DB { return routeDB },
		DBPath: func() string { return routeDBPath },
	})
	cookie := app.authenticate(t)
	server := Server{Name: "srv-facts-injected", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	app.Deps.ServerState.Lock()
	app.Deps.ServerState.SetServers([]Server{server})
	app.Deps.ServerState.SetStatusMap(map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle"},
	})
	app.Deps.ServerState.Unlock()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/servers/"+server.Name+"/facts/refresh", nil)
	req.AddCookie(cookie)
	markSameOriginAuthRequest(req)
	app.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("facts refresh status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var routeCount int
	if err := routeDB.QueryRow("SELECT COUNT(1) FROM server_facts WHERE server_name = ?", server.Name).Scan(&routeCount); err != nil {
		t.Fatalf("query route facts: %v", err)
	}
	if routeCount != 1 {
		t.Fatalf("route facts count = %d, want 1", routeCount)
	}
	var globalCount int
	if err := getDB().QueryRow("SELECT COUNT(1) FROM server_facts WHERE server_name = ?", server.Name).Scan(&globalCount); err != nil {
		t.Fatalf("query global facts: %v", err)
	}
	if globalCount != 0 {
		t.Fatalf("global facts count = %d, want 0", globalCount)
	}
}

func performInvalidSetupRequest(handler http.Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"username":"","password":"short"}`))
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	return rec
}

func prepareInjectedAppDB(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS servers (
			name TEXT PRIMARY KEY,
			host TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 22,
			user TEXT NOT NULL,
			pass_enc TEXT NOT NULL,
			key_enc TEXT NOT NULL DEFAULT '',
			key_path TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT ''
		)
	`); err != nil {
		return err
	}
	return ensureSchema(db)
}

func TestSetupRouterWithDepsPreservesRouteInventory(t *testing.T) {
	app := newIsolatedTestApp(t)

	registered := make(map[string]bool)
	for _, route := range app.Router.Routes() {
		registered[route.Method+" "+route.Path] = true
	}
	for _, route := range criticalRouteInventory() {
		key := route.method + " " + route.path
		if !registered[key] {
			t.Fatalf("route %s was not registered", key)
		}
	}
}

func TestAuthenticatedFixturePreservesServerWireShape(t *testing.T) {
	app := newIsolatedTestApp(t)
	sessionCookie := app.authenticate(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	req.AddCookie(sessionCookie)
	app.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/servers status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Body.String(); got != "[]" {
		t.Fatalf("GET /api/servers body = %q, want []", got)
	}
}

func TestActionRoutesUseInjectedUpdateServiceJobManager(t *testing.T) {
	gin.SetMode(gin.TestMode)
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "app.db"))

	appDB := getDB()
	globalJM := newJobManager(appDB)

	routeDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "route-jobs.db"))
	if err != nil {
		t.Fatalf("open route jobs db: %v", err)
	}
	t.Cleanup(func() { _ = routeDB.Close() })
	if err := ensureJobSchema(routeDB); err != nil {
		t.Fatalf("ensure route job schema: %v", err)
	}
	routeJM := newJobManager(routeDB)

	var command string
	server := Server{Name: "srv-injected-jobs", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	routeState := newServerState()
	updateDeps := testUpdateServiceDeps(t)
	updateDeps.ServerState = routeState
	updateDeps.CurrentJobManager = func() *JobManager { return routeJM }
	updateDeps.RunSSHCommandWithTimeout = func(_ sshConnection, cmd string, _ io.Reader, _ time.Duration) (string, string, error) {
		command = cmd
		return "removed packages", "", nil
	}
	router, err := setupRouterWithDeps(AppDeps{
		DB:            func() *sql.DB { return appDB },
		JobManager:    globalJM,
		ServerState:   routeState,
		UpdateService: NewUpdateService(updateDeps),
	})
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
	routeState.Lock()
	routeState.SetServers([]Server{server})
	routeState.SetStatusMap(map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	})
	routeState.Unlock()
	handler := sessionManager.LoadAndSave(router)
	app := &testApp{Handler: handler}
	sessionCookie := app.authenticate(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/autoremove/"+server.Name, nil)
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("autoremove status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal autoremove response: %v", err)
	}
	if resp.JobID == "" {
		t.Fatalf("response job_id is empty")
	}

	waitForUpdateRunners()
	if command != aptAutoremoveCmd {
		t.Fatalf("command = %q, want %q", command, aptAutoremoveCmd)
	}
	routeJob, err := routeJM.GetJob(resp.JobID)
	if err != nil {
		t.Fatalf("injected job manager missing route job %q: %v", resp.JobID, err)
	}
	if routeJob.Status != jobStatusSucceeded {
		t.Fatalf("injected job status = %q, want %q", routeJob.Status, jobStatusSucceeded)
	}
	if _, err := globalJM.GetJob(resp.JobID); err == nil {
		t.Fatalf("global job manager unexpectedly contains route job %q", resp.JobID)
	}
}

func TestPolicyRoutesUseInjectedPolicyServiceForList(t *testing.T) {
	policy := UpdatePolicy{
		ID:            77,
		Name:          "Injected policy",
		Enabled:       true,
		IncludeTags:   []string{"prod"},
		PackageScope:  updatePolicyPackageScopeSecurity,
		ExecutionMode: updatePolicyExecutionScanOnly,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     "02:15",
	}
	service := NewPolicyService(PolicyServiceDeps{
		ListPolicies: func() ([]UpdatePolicy, error) {
			return []UpdatePolicy{policy}, nil
		},
		SnapshotServers: func() []Server {
			return []Server{{Name: "srv-prod", Tags: []string{"prod"}}}
		},
		LoadOverrides: func() (map[int64]map[string]bool, error) {
			return map[int64]map[string]bool{}, nil
		},
	})
	app := newTestAppWithDeps(t, filepath.Join(t.TempDir(), "policy-list.db"), AppDeps{
		PolicyService:              service,
		AppTimezoneDisplayName:     func() string { return "Injected/TZ" },
		AppTimezoneResolvedName:    func() string { return "Injected/TZ" },
		InitializeMaintenanceState: func() error { return nil },
	})
	sessionCookie := app.authenticate(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/update-policies", nil)
	req.AddCookie(sessionCookie)
	app.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("policy list status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp struct {
		Items            []UpdatePolicy `json:"items"`
		Timezone         string         `json:"timezone"`
		ResolvedTimezone string         `json:"resolved_timezone"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal policy list: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].ID != policy.ID {
		t.Fatalf("policy list items = %+v, want injected policy", resp.Items)
	}
	if len(resp.Items[0].MatchedServers) != 1 || resp.Items[0].MatchedServers[0] != "srv-prod" {
		t.Fatalf("matched servers = %+v, want [srv-prod]", resp.Items[0].MatchedServers)
	}
	if resp.Timezone != "Injected/TZ" || resp.ResolvedTimezone != "Injected/TZ" {
		t.Fatalf("timezone fields = %q/%q, want injected names", resp.Timezone, resp.ResolvedTimezone)
	}
}

func TestAuditRoutesUseInjectedAuditService(t *testing.T) {
	auditDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit-routes.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = auditDB.Close() })
	ensureAuditEventsTestSchema(t, auditDB)
	auditSvc := NewAuditService(func() *sql.DB { return auditDB }, nil, nil)
	if err := auditSvc.Write(AuditEvent{
		CreatedAt:  "2026-05-17T12:00:00Z",
		Actor:      "tester",
		Action:     "route.injected",
		TargetType: "server",
		TargetName: "srv-audit",
		Status:     "success",
		Message:    "from injected audit service",
		MetaJSON:   `{"source":"injected"}`,
	}); err != nil {
		t.Fatalf("write injected audit event: %v", err)
	}
	var auditID int64
	if err := auditDB.QueryRow("SELECT id FROM audit_events WHERE action = ?", "route.injected").Scan(&auditID); err != nil {
		t.Fatalf("load injected audit id: %v", err)
	}

	app := newTestAppWithDeps(t, filepath.Join(t.TempDir(), "audit-app.db"), AppDeps{
		AuditService: auditSvc,
	})
	sessionCookie := app.authenticate(t)

	listRec := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/audit-events?action=route.injected", nil)
	listReq.AddCookie(sessionCookie)
	app.Handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("audit list status = %d, want %d (body=%s)", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var listResp struct {
		Items []AuditEvent `json:"items"`
		Total int          `json:"total"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal audit list: %v", err)
	}
	if listResp.Total != 1 || len(listResp.Items) != 1 || listResp.Items[0].Action != "route.injected" {
		t.Fatalf("audit list response = %+v, want injected event", listResp)
	}

	reportRec := httptest.NewRecorder()
	reportReq := httptest.NewRequest(http.MethodGet, "/api/reports/audit/"+strconvFormatInt(auditID), nil)
	reportReq.AddCookie(sessionCookie)
	app.Handler.ServeHTTP(reportRec, reportReq)
	if reportRec.Code != http.StatusOK {
		t.Fatalf("audit report status = %d, want %d (body=%s)", reportRec.Code, http.StatusOK, reportRec.Body.String())
	}
	if body := reportRec.Body.String(); !strings.Contains(body, "# Audit Event Report #"+strconvFormatInt(auditID)) || !strings.Contains(body, `"source": "injected"`) {
		t.Fatalf("audit report body missing injected content:\n%s", body)
	}
}

func authUserExistsInDB(t *testing.T, dbPath string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM auth_users").Scan(&count); err != nil {
		t.Fatalf("count auth users in %s: %v", dbPath, err)
	}
	return count > 0
}

func serverExistsInDB(t *testing.T, dbPath, name string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM servers WHERE name = ?", name).Scan(&count); err != nil {
		t.Fatalf("count server %q in %s: %v", name, dbPath, err)
	}
	return count > 0
}

func policyExistsInDB(t *testing.T, dbPath, name string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM update_policies WHERE name = ?", name).Scan(&count); err != nil {
		t.Fatalf("count policy %q in %s: %v", name, dbPath, err)
	}
	return count > 0
}

func settingExistsInDB(t *testing.T, dbPath, key string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM settings WHERE key = ?", key).Scan(&count); err != nil {
		t.Fatalf("count setting %q in %s: %v", key, dbPath, err)
	}
	return count > 0
}

func ensureAuditEventsTestSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TEXT NOT NULL,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			target_type TEXT NOT NULL,
			target_name TEXT NOT NULL,
			status TEXT NOT NULL,
			message TEXT NOT NULL,
			meta_json TEXT NOT NULL DEFAULT '{}',
			request_id TEXT NOT NULL DEFAULT '',
			client_ip TEXT NOT NULL DEFAULT ''
		)
	`); err != nil {
		t.Fatalf("create audit_events test schema: %v", err)
	}
}
