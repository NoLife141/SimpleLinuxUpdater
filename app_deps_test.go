package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
