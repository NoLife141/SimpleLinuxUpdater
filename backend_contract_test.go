package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func performContractRequest(handler http.Handler, method, path string, body *bytes.Buffer, cookie *http.Cookie, sameOrigin bool) *httptest.ResponseRecorder {
	if body == nil {
		body = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, body)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if body.Len() > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if sameOrigin {
		markSameOriginAuthRequest(req)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeContractJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON object: %v\nbody=%s", err, rec.Body.String())
	}
	return payload
}

func TestBackendContractRouteGroups(t *testing.T) {
	app := newIsolatedTestApp(t)
	registered := make(map[string]bool)
	for _, route := range app.Router.Routes() {
		registered[route.Method+" "+route.Path] = true
	}

	groups := map[string][]routeInventoryEntry{
		"public": {
			{http.MethodGet, "/setup"},
			{http.MethodGet, "/login"},
			{http.MethodPost, "/api/auth/setup"},
			{http.MethodPost, "/api/auth/login"},
			{http.MethodGet, "/api/auth/status"},
			{http.MethodGet, "/api/maintenance"},
			{http.MethodGet, "/metrics"},
		},
		"pages": {
			{http.MethodGet, "/"},
			{http.MethodGet, "/manage"},
			{http.MethodGet, "/observability"},
			{http.MethodGet, "/admin"},
		},
		"auth_settings_backup": {
			{http.MethodPost, "/api/auth/logout"},
			{http.MethodGet, "/api/auth/sessions"},
			{http.MethodPut, "/api/auth/password"},
			{http.MethodDelete, "/api/auth/sessions"},
			{http.MethodGet, "/api/metrics/token"},
			{http.MethodPost, "/api/metrics/token"},
			{http.MethodDelete, "/api/metrics/token"},
			{http.MethodGet, "/api/backup/status"},
			{http.MethodPost, "/api/backup/export"},
			{http.MethodPost, "/api/backup/restore"},
			{http.MethodGet, "/api/dashboard/events"},
			{http.MethodGet, "/api/app-settings/timezone"},
			{http.MethodPut, "/api/app-settings/timezone"},
		},
		"policy_audit_observability": {
			{http.MethodGet, "/api/update-policies"},
			{http.MethodPost, "/api/update-policies"},
			{http.MethodGet, "/api/update-policies/runs"},
			{http.MethodGet, "/api/update-policies/settings"},
			{http.MethodPut, "/api/update-policies/settings"},
			{http.MethodGet, "/api/update-policies/:id/overrides"},
			{http.MethodPut, "/api/update-policies/:id/overrides/:server"},
			{http.MethodPut, "/api/update-policies/:id"},
			{http.MethodDelete, "/api/update-policies/:id"},
			{http.MethodGet, "/api/audit-events"},
			{http.MethodPost, "/api/audit-events/prune"},
			{http.MethodGet, "/api/reports/audit/:id"},
			{http.MethodGet, "/api/reports/jobs/:id"},
			{http.MethodGet, "/api/observability/summary"},
			{http.MethodGet, "/api/dashboard/summary"},
		},
		"servers_actions_hostkeys": {
			{http.MethodGet, "/api/servers"},
			{http.MethodPost, "/api/servers"},
			{http.MethodPut, "/api/servers/:name"},
			{http.MethodDelete, "/api/servers/:name"},
			{http.MethodDelete, "/api/servers/:name/password"},
			{http.MethodPost, "/api/servers/:name/key"},
			{http.MethodDelete, "/api/servers/:name/key"},
			{http.MethodGet, "/api/keys/global"},
			{http.MethodPost, "/api/keys/global"},
			{http.MethodDelete, "/api/keys/global"},
			{http.MethodPost, "/api/servers/:name/facts/refresh"},
			{http.MethodPost, "/api/hostkeys/scan"},
			{http.MethodPost, "/api/hostkeys/trust"},
			{http.MethodPost, "/api/hostkeys/clear"},
			{http.MethodPost, "/api/update/:name"},
			{http.MethodPost, "/api/autoremove/:name"},
			{http.MethodPost, "/api/sudoers/:name"},
			{http.MethodPost, "/api/sudoers/disable/:name"},
			{http.MethodPost, "/api/approve/:name"},
			{http.MethodPost, "/api/approve-security/:name"},
			{http.MethodPost, "/api/cancel/:name"},
		},
	}

	for groupName, routes := range groups {
		t.Run(groupName, func(t *testing.T) {
			for _, route := range routes {
				key := route.method + " " + route.path
				if !registered[key] {
					t.Fatalf("route %s was not registered", key)
				}
			}
		})
	}
}

func TestBackendContractAuthAndMiddleware(t *testing.T) {
	app := newIsolatedTestApp(t)
	sessionCookie := app.authenticate(t)

	t.Run("protected API without session is unauthorized", func(t *testing.T) {
		rec := performContractRequest(app.Handler, http.MethodGet, "/api/servers", nil, nil, false)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET /api/servers without session status = %d, want %d (body=%s)", rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
		payload := decodeContractJSON(t, rec)
		if payload["error"] != "authentication required" || payload["setup_required"] != false {
			t.Fatalf("unauthorized payload = %+v", payload)
		}
	})

	t.Run("protected HTML without session redirects to login", func(t *testing.T) {
		rec := performContractRequest(app.Handler, http.MethodGet, "/manage", nil, nil, false)
		if rec.Code != http.StatusFound {
			t.Fatalf("GET /manage without session status = %d, want %d", rec.Code, http.StatusFound)
		}
		if got := rec.Header().Get("Location"); got != "/login" {
			t.Fatalf("GET /manage redirect = %q, want /login", got)
		}
	})

	t.Run("protected write without same origin is rejected", func(t *testing.T) {
		body := bytes.NewBufferString(`{"name":"No origin","target_servers":["srv"],"package_scope":"security","execution_mode":"scan_only","cadence_kind":"daily","time_local":"02:00"}`)
		rec := performContractRequest(app.Handler, http.MethodPost, "/api/update-policies", body, sessionCookie, false)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("POST /api/update-policies without same-origin status = %d, want %d (body=%s)", rec.Code, http.StatusForbidden, rec.Body.String())
		}
		payload := decodeContractJSON(t, rec)
		if payload["error"] != "cross-site write request denied" {
			t.Fatalf("same-origin rejection payload = %+v", payload)
		}
	})

	t.Run("public auth status remains reachable", func(t *testing.T) {
		rec := performContractRequest(app.Handler, http.MethodGet, "/api/auth/status", nil, nil, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/auth/status status = %d, want %d", rec.Code, http.StatusOK)
		}
		payload := decodeContractJSON(t, rec)
		if payload["authenticated"] != false || payload["setup_required"] != false {
			t.Fatalf("auth status payload = %+v", payload)
		}
	})
}

func TestBackendContractCoreAPIWireShapes(t *testing.T) {
	app := newIsolatedTestApp(t)
	sessionCookie := app.authenticate(t)

	t.Run("fresh servers list", func(t *testing.T) {
		rec := performContractRequest(app.Handler, http.MethodGet, "/api/servers", nil, sessionCookie, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/servers status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
		}
		if strings.TrimSpace(rec.Body.String()) != "[]" {
			t.Fatalf("GET /api/servers body = %q, want []", rec.Body.String())
		}
	})

	t.Run("auth status and sessions", func(t *testing.T) {
		statusRec := performContractRequest(app.Handler, http.MethodGet, "/api/auth/status", nil, sessionCookie, false)
		if statusRec.Code != http.StatusOK {
			t.Fatalf("GET /api/auth/status status = %d, want %d", statusRec.Code, http.StatusOK)
		}
		status := decodeContractJSON(t, statusRec)
		for _, key := range []string{"authenticated", "username", "setup_required"} {
			if _, ok := status[key]; !ok {
				t.Fatalf("auth status missing key %q in %+v", key, status)
			}
		}

		sessionsRec := performContractRequest(app.Handler, http.MethodGet, "/api/auth/sessions", nil, sessionCookie, false)
		if sessionsRec.Code != http.StatusOK {
			t.Fatalf("GET /api/auth/sessions status = %d, want %d", sessionsRec.Code, http.StatusOK)
		}
		sessions := decodeContractJSON(t, sessionsRec)
		if _, ok := sessions["session_count"]; !ok {
			t.Fatalf("sessions payload missing session_count: %+v", sessions)
		}
	})

	t.Run("backup status and export", func(t *testing.T) {
		statusRec := performContractRequest(app.Handler, http.MethodGet, "/api/backup/status", nil, sessionCookie, false)
		if statusRec.Code != http.StatusOK {
			t.Fatalf("GET /api/backup/status status = %d, want %d", statusRec.Code, http.StatusOK)
		}
		status := decodeContractJSON(t, statusRec)
		for _, key := range []string{"db_path", "config_path", "known_hosts_path", "known_hosts_exists"} {
			if _, ok := status[key]; !ok {
				t.Fatalf("backup status missing key %q in %+v", key, status)
			}
		}

		getEncryptionKey()
		exportBody := bytes.NewBufferString(`{"passphrase":"very-strong-passphrase","include_known_hosts":false}`)
		exportRec := performContractRequest(app.Handler, http.MethodPost, "/api/backup/export", exportBody, sessionCookie, true)
		if exportRec.Code != http.StatusOK {
			t.Fatalf("POST /api/backup/export status = %d, want %d (body=%s)", exportRec.Code, http.StatusOK, exportRec.Body.String())
		}
		if contentType := exportRec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/octet-stream") {
			t.Fatalf("backup export Content-Type = %q, want application/octet-stream", contentType)
		}
		if disposition := exportRec.Header().Get("Content-Disposition"); !strings.Contains(disposition, ".slubkp") {
			t.Fatalf("backup export Content-Disposition = %q, want .slubkp filename", disposition)
		}
		if exportRec.Body.Len() == 0 {
			t.Fatalf("backup export body is empty")
		}
	})
}

func TestBackendContractReportsAndPolicies(t *testing.T) {
	app := newIsolatedTestApp(t)
	sessionCookie := app.authenticate(t)

	if err := writeAuditEvent(AuditEvent{
		CreatedAt:  "2026-05-18T12:00:00Z",
		Actor:      "admin",
		Action:     updateCompleteAction,
		TargetType: "server",
		TargetName: "srv-contract",
		Status:     "success",
		Message:    "contract event",
		MetaJSON:   `{"contract":true}`,
	}); err != nil {
		t.Fatalf("writeAuditEvent() error = %v", err)
	}
	var auditID int64
	if err := getDB().QueryRow("SELECT id FROM audit_events WHERE target_name = ? ORDER BY id DESC LIMIT 1", "srv-contract").Scan(&auditID); err != nil {
		t.Fatalf("query audit id: %v", err)
	}
	job, err := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: "srv-contract",
		Actor:      "admin",
		Status:     jobStatusSucceeded,
		Summary:    "Contract job",
		LogsText:   "Contract logs",
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}

	t.Run("audit list and report", func(t *testing.T) {
		listRec := performContractRequest(app.Handler, http.MethodGet, "/api/audit-events?target=srv-contract&page_size=20", nil, sessionCookie, false)
		if listRec.Code != http.StatusOK {
			t.Fatalf("GET /api/audit-events status = %d, want %d (body=%s)", listRec.Code, http.StatusOK, listRec.Body.String())
		}
		list := decodeContractJSON(t, listRec)
		for _, key := range []string{"items", "page", "page_size", "total"} {
			if _, ok := list[key]; !ok {
				t.Fatalf("audit list missing key %q in %+v", key, list)
			}
		}

		reportRec := performContractRequest(app.Handler, http.MethodGet, "/api/reports/audit/"+strconvFormatInt(auditID), nil, sessionCookie, false)
		if reportRec.Code != http.StatusOK {
			t.Fatalf("GET /api/reports/audit/:id status = %d, want %d", reportRec.Code, http.StatusOK)
		}
		if mediaType, _, err := mime.ParseMediaType(reportRec.Header().Get("Content-Type")); err != nil || mediaType != "text/markdown" {
			t.Fatalf("audit report Content-Type = %q, media=%q err=%v", reportRec.Header().Get("Content-Type"), mediaType, err)
		}
		if !strings.Contains(reportRec.Body.String(), "# Audit Event Report #"+strconvFormatInt(auditID)) {
			t.Fatalf("audit report body missing title:\n%s", reportRec.Body.String())
		}
	})

	t.Run("job report", func(t *testing.T) {
		reportRec := performContractRequest(app.Handler, http.MethodGet, "/api/reports/jobs/"+job.ID, nil, sessionCookie, false)
		if reportRec.Code != http.StatusOK {
			t.Fatalf("GET /api/reports/jobs/:id status = %d, want %d", reportRec.Code, http.StatusOK)
		}
		if !strings.Contains(reportRec.Body.String(), "# Update Job Report "+job.ID) || !strings.Contains(reportRec.Body.String(), "Contract logs") {
			t.Fatalf("job report body missing expected content:\n%s", reportRec.Body.String())
		}
	})

	t.Run("policy list create settings and runs", func(t *testing.T) {
		createBody := bytes.NewBufferString(`{"name":"Contract scan","enabled":false,"target_servers":["srv-contract"],"package_scope":"security","execution_mode":"scan_only","cadence_kind":"daily","time_local":"02:15","weekdays":[],"approval_timeout_minutes":0,"policy_blackouts":[]}`)
		createRec := performContractRequest(app.Handler, http.MethodPost, "/api/update-policies", createBody, sessionCookie, true)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("POST /api/update-policies status = %d, want %d (body=%s)", createRec.Code, http.StatusCreated, createRec.Body.String())
		}
		created := decodeContractJSON(t, createRec)
		for _, key := range []string{"id", "name", "enabled", "target_servers", "package_scope", "execution_mode", "cadence_kind", "time_local"} {
			if _, ok := created[key]; !ok {
				t.Fatalf("created policy missing key %q in %+v", key, created)
			}
		}

		listRec := performContractRequest(app.Handler, http.MethodGet, "/api/update-policies", nil, sessionCookie, false)
		if listRec.Code != http.StatusOK {
			t.Fatalf("GET /api/update-policies status = %d, want %d", listRec.Code, http.StatusOK)
		}
		list := decodeContractJSON(t, listRec)
		for _, key := range []string{"items", "timezone", "resolved_timezone"} {
			if _, ok := list[key]; !ok {
				t.Fatalf("policy list missing key %q in %+v", key, list)
			}
		}

		settingsRec := performContractRequest(app.Handler, http.MethodGet, "/api/update-policies/settings", nil, sessionCookie, false)
		if settingsRec.Code != http.StatusOK {
			t.Fatalf("GET /api/update-policies/settings status = %d, want %d", settingsRec.Code, http.StatusOK)
		}
		settings := decodeContractJSON(t, settingsRec)
		for _, key := range []string{"timezone", "resolved_timezone", "global_blackouts"} {
			if _, ok := settings[key]; !ok {
				t.Fatalf("policy settings missing key %q in %+v", key, settings)
			}
		}

		runsRec := performContractRequest(app.Handler, http.MethodGet, "/api/update-policies/runs?limit=10", nil, sessionCookie, false)
		if runsRec.Code != http.StatusOK {
			t.Fatalf("GET /api/update-policies/runs status = %d, want %d", runsRec.Code, http.StatusOK)
		}
		runs := decodeContractJSON(t, runsRec)
		for _, key := range []string{"items", "timezone", "resolved_timezone"} {
			if _, ok := runs[key]; !ok {
				t.Fatalf("policy runs missing key %q in %+v", key, runs)
			}
		}
	})
}

func TestBackendContractUpdateApproveCancel(t *testing.T) {
	preserveServerState(t)
	updateDeps := testUpdateServiceDeps(t)
	updateDeps.CurrentJobManager = currentJobManager
	updateDeps.GetUpgradable = func(sshConnection, time.Duration) ([]PendingUpdate, []string, error) {
		return nil, nil, nil
	}
	updateDeps.RunSSHCommandWithTimeout = func(sshConnection, string, io.Reader, time.Duration) (string, string, error) {
		return "", "", nil
	}
	app := newTestAppWithDeps(t, filepath.Join(t.TempDir(), "contract-update.db"), AppDeps{
		UpdateService: NewUpdateService(updateDeps),
	})
	sessionCookie := app.authenticate(t)

	server := Server{Name: "srv-contract-update", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	func() {
		mu.Lock()
		defer mu.Unlock()
		servers = []Server{server}
		statusMap = map[string]*ServerStatus{
			server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
		}
	}()

	startRec := performContractRequest(app.Handler, http.MethodPost, "/api/update/"+server.Name, nil, sessionCookie, true)
	if startRec.Code != http.StatusOK {
		t.Fatalf("POST /api/update/:name status = %d, want %d (body=%s)", startRec.Code, http.StatusOK, startRec.Body.String())
	}
	startPayload := decodeContractJSON(t, startRec)
	if _, ok := startPayload["job_id"]; !ok {
		t.Fatalf("update start payload missing job_id: %+v", startPayload)
	}
	waitForUpdateRunners()

	jm := currentJobManager()
	if jm == nil {
		t.Fatalf("currentJobManager() is nil")
	}
	for _, tc := range []struct {
		name   string
		path   string
		server string
	}{
		{name: "approve", path: "/api/approve/srv-contract-approve", server: "srv-contract-approve"},
		{name: "cancel", path: "/api/cancel/srv-contract-cancel", server: "srv-contract-cancel"},
	} {
		t.Run(tc.name+" success and conflict", func(t *testing.T) {
			func() {
				mu.Lock()
				defer mu.Unlock()
				servers = append(servers, Server{Name: tc.server, Host: "example.net", Port: 22, User: "root", Pass: "pw"})
				statusMap[tc.server] = &ServerStatus{Name: tc.server, Status: "pending_approval", Logs: "pending", Upgradable: []string{"bash"}}
			}()
			if _, err := jm.CreateJob(JobCreateParams{
				Kind:       jobKindUpdate,
				ServerName: tc.server,
				Actor:      "admin",
				Status:     jobStatusWaitingApproval,
				Phase:      jobPhaseApprovalWait,
				Summary:    "Waiting for approval",
				LogsText:   "pending",
			}); err != nil {
				t.Fatalf("CreateJob(%s) error = %v", tc.server, err)
			}

			successRec := performContractRequest(app.Handler, http.MethodPost, tc.path, nil, sessionCookie, true)
			if successRec.Code != http.StatusOK {
				t.Fatalf("POST %s status = %d, want %d (body=%s)", tc.path, successRec.Code, http.StatusOK, successRec.Body.String())
			}
			if _, ok := decodeContractJSON(t, successRec)["message"]; !ok {
				t.Fatalf("POST %s success payload missing message: %s", tc.path, successRec.Body.String())
			}
			waitForUpdateRunners()

			conflictRec := performContractRequest(app.Handler, http.MethodPost, tc.path, nil, sessionCookie, true)
			if conflictRec.Code != http.StatusConflict {
				t.Fatalf("POST %s second status = %d, want %d (body=%s)", tc.path, conflictRec.Code, http.StatusConflict, conflictRec.Body.String())
			}
			if decodeContractJSON(t, conflictRec)["error"] != "Server not pending approval" {
				t.Fatalf("POST %s conflict payload = %s", tc.path, conflictRec.Body.String())
			}
		})
	}
}
