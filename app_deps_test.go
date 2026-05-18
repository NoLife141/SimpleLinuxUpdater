package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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

	server := Server{Name: "srv-injected-jobs", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	var command string
	updateDeps := testUpdateServiceDeps(t)
	updateDeps.CurrentJobManager = func() *JobManager { return routeJM }
	updateDeps.RunSSHCommandWithTimeout = func(_ sshConnection, cmd string, _ io.Reader, _ time.Duration) (string, string, error) {
		command = cmd
		return "removed packages", "", nil
	}
	router, err := setupRouterWithDeps(AppDeps{
		DB:            func() *sql.DB { return appDB },
		JobManager:    globalJM,
		UpdateService: NewUpdateService(updateDeps),
	})
	if err != nil {
		t.Fatalf("setupRouterWithDeps() unexpected error: %v", err)
	}
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
