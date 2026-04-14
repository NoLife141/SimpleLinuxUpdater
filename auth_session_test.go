package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/gin-gonic/gin"
)

const (
	testPasswordStrong = "StrongPass123" // gitleaks:allow
	testPasswordAlt    = "StrongPass999" // gitleaks:allow
)

func preserveSessionState(t *testing.T) {
	t.Helper()
	orig := sessionManager
	t.Cleanup(func() {
		sessionManager = orig
	})
}

func preserveRateLimiterState(t *testing.T) {
	t.Helper()
	origLogin := loginRateLimiter
	origSetup := setupRateLimiter
	origMetrics := metricsRateLimiter

	testLogin := NewAuthRateLimiter(authRateLimitWindow, authLoginRateLimitMaxAttempts)
	testSetup := NewAuthRateLimiter(authRateLimitWindow, authSetupRateLimitMaxAttempts)
	testMetrics := NewAuthRateLimiter(metricsRateLimitWindow, metricsRateLimitMaxAttempts)
	loginRateLimiter = testLogin
	setupRateLimiter = testSetup
	metricsRateLimiter = testMetrics

	t.Cleanup(func() {
		testLogin.Stop()
		testSetup.Stop()
		testMetrics.Stop()
		loginRateLimiter = origLogin
		setupRateLimiter = origSetup
		metricsRateLimiter = origMetrics
	})
}

func preserveMetricsTokenState(t *testing.T) {
	t.Helper()
	metricsBearerTokenHashMu.RLock()
	origHash := metricsBearerTokenHash
	origLoaded := metricsBearerTokenHashLoaded
	origDBPath := metricsBearerTokenHashDBPath
	metricsBearerTokenHashMu.RUnlock()

	t.Cleanup(func() {
		metricsBearerTokenHashMu.Lock()
		metricsBearerTokenHash = origHash
		metricsBearerTokenHashLoaded = origLoaded
		metricsBearerTokenHashDBPath = origDBPath
		metricsBearerTokenHashMu.Unlock()
	})
}

func markSameOriginAuthRequest(req *http.Request) {
	if req == nil {
		return
	}
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req.Header.Set("Referer", "http://localhost/")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
}

func markSameOriginAuthRequestWithoutSecFetch(req *http.Request) {
	if req == nil {
		return
	}
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req.Header.Set("Referer", "http://localhost/")
	req.Header.Del("Sec-Fetch-Site")
}

func testSessionCookieFromRecorder(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	if sessionManager == nil {
		t.Fatalf("sessionManager is nil; cannot locate session cookie")
	}
	expectedName := sessionManager.Cookie.Name
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == expectedName {
			return cookie
		}
	}
	t.Fatalf("session cookie %q not found in response", expectedName)
	return nil
}

func assertSecurityHeaders(t *testing.T, h http.Header, wantHSTS bool) {
	t.Helper()
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
	if got := h.Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Fatalf("Referrer-Policy = %q, want %q", got, "strict-origin-when-cross-origin")
	}
	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want %q", got, "DENY")
	}
	if got := strings.TrimSpace(h.Get("Content-Security-Policy")); got != defaultContentSecurityPolicy {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, defaultContentSecurityPolicy)
	}

	if wantHSTS {
		if got := h.Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
			t.Fatalf("Strict-Transport-Security = %q, want %q", got, "max-age=31536000; includeSubDomains")
		}
		return
	}
	if got := h.Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("Strict-Transport-Security = %q, want empty", got)
	}
}

func TestBackupRestoreBarrierMiddlewareBlocksReadsAndSerializesBackupRoutes(t *testing.T) {
	t.Run("get waits behind restore lock", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Use(backupRestoreBarrierMiddleware())
		r.GET("/probe", func(c *gin.Context) {
			c.Status(http.StatusNoContent)
		})

		backupRestoreMu.Lock()
		defer backupRestoreMu.Unlock()

		done := make(chan int, 1)
		go func() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/probe", nil)
			r.ServeHTTP(rec, req)
			done <- rec.Code
		}()

		select {
		case code := <-done:
			t.Fatalf("GET completed while restore lock held with status %d", code)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("backup route waits behind shared readers", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Use(backupRestoreBarrierMiddleware())
		r.POST("/api/backup/restore", func(c *gin.Context) {
			c.Status(http.StatusNoContent)
		})

		backupRestoreMu.RLock()
		done := make(chan int, 1)
		go func() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/backup/restore", nil)
			r.ServeHTTP(rec, req)
			done <- rec.Code
		}()

		select {
		case code := <-done:
			backupRestoreMu.RUnlock()
			t.Fatalf("backup restore completed while shared lock held with status %d", code)
		case <-time.After(100 * time.Millisecond):
		}

		backupRestoreMu.RUnlock()
		select {
		case code := <-done:
			if code != http.StatusNoContent {
				t.Fatalf("backup restore status = %d, want %d", code, http.StatusNoContent)
			}
		case <-time.After(time.Second):
			t.Fatalf("backup restore did not complete after shared lock release")
		}
	})
}

func TestMaintenanceModeBlocksRoutesAndAllowsStatusEndpoint(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "maintenance-mode.db"))

	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionHandler(r)

	state := MaintenanceState{
		Active:    true,
		Kind:      jobKindBackupRestore,
		JobID:     "job-maintenance-test",
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Actor:     "admin",
		Message:   "Backup restore in progress.",
	}
	setCurrentMaintenanceState(state)

	maintenanceRec := httptest.NewRecorder()
	maintenanceReq := httptest.NewRequest(http.MethodGet, "/api/maintenance", nil)
	handler.ServeHTTP(maintenanceRec, maintenanceReq)
	if maintenanceRec.Code != http.StatusOK {
		t.Fatalf("/api/maintenance status = %d, want %d", maintenanceRec.Code, http.StatusOK)
	}
	var gotState MaintenanceState
	if err := json.Unmarshal(maintenanceRec.Body.Bytes(), &gotState); err != nil {
		t.Fatalf("unmarshal maintenance state: %v", err)
	}
	if !gotState.Active || gotState.JobID != state.JobID || gotState.Kind != state.Kind {
		t.Fatalf("maintenance state = %+v, want active job=%q kind=%q", gotState, state.JobID, state.Kind)
	}

	apiRec := httptest.NewRecorder()
	apiReq := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	handler.ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/api/auth/status during maintenance = %d, want %d (body=%s)", apiRec.Code, http.StatusServiceUnavailable, apiRec.Body.String())
	}
	if !strings.Contains(apiRec.Body.String(), `"maintenance":true`) {
		t.Fatalf("maintenance API response missing maintenance flag: %s", apiRec.Body.String())
	}

	htmlRec := httptest.NewRecorder()
	htmlReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	handler.ServeHTTP(htmlRec, htmlReq)
	if htmlRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/login during maintenance = %d, want %d", htmlRec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(htmlRec.Body.String(), "Maintenance Mode") {
		t.Fatalf("maintenance HTML page missing title: %s", htmlRec.Body.String())
	}
}

func TestValidatePasswordPolicy(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "empty string", value: "", wantErr: true},
		{name: "too short", value: "Abc123", wantErr: true},
		{name: "min valid length", value: strings.Repeat("A", authMinPasswordLen-1) + "1", wantErr: false},
		{name: "missing letter", value: strings.Repeat("1", 10), wantErr: true},
		{name: "missing digit", value: strings.Repeat("A", 10), wantErr: true},
		{name: "max valid length", value: strings.Repeat("A", 63) + "1", wantErr: false},
		{name: "too long", value: strings.Repeat("A", 64) + "1", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := validatePasswordPolicy(tc.value)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validatePasswordPolicy(%q) err=%v, wantErr=%v", tc.value, err, tc.wantErr)
			}
		})
	}
}

func TestSameOriginAuthRequestAllowsOriginOrRefererWithoutSecFetchSite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name    string
		origin  string
		referer string
		want    bool
	}{
		{name: "origin and referer", origin: "http://localhost", referer: "http://localhost/setup", want: true},
		{name: "origin only", origin: "http://localhost", referer: "", want: true},
		{name: "referer only", origin: "", referer: "http://localhost/setup", want: true},
		{name: "missing both", origin: "", referer: "", want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", nil)
			req.Host = "localhost"
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			ctx.Request = req
			if got := sameOriginAuthRequest(ctx); got != tt.want {
				t.Fatalf("sameOriginAuthRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetupRequiredAndSingleUserLifecycle(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "auth-session.db"))

	required, err := setupRequired()
	if err != nil {
		t.Fatalf("setupRequired() unexpected error: %v", err)
	}
	if !required {
		t.Fatalf("setupRequired() = false, want true on empty auth_users")
	}

	if err := createInitialUser("admin", testPasswordStrong); err != nil {
		t.Fatalf("createInitialUser() unexpected error: %v", err)
	}

	required, err = setupRequired()
	if err != nil {
		t.Fatalf("setupRequired() after setup unexpected error: %v", err)
	}
	if required {
		t.Fatalf("setupRequired() = true, want false after initial user creation")
	}

	username, passwordHash, exists, err := getSingleUser()
	if err != nil {
		t.Fatalf("getSingleUser() unexpected error: %v", err)
	}
	if !exists {
		t.Fatalf("getSingleUser() exists = false, want true")
	}
	if username != "admin" {
		t.Fatalf("getSingleUser() username = %q, want %q", username, "admin")
	}
	if passwordHash == "" || strings.Contains(passwordHash, testPasswordStrong) {
		t.Fatalf("getSingleUser() password hash appears invalid: %q", passwordHash)
	}

	ok, err := authenticateUser("admin", testPasswordStrong)
	if err != nil {
		t.Fatalf("authenticateUser(valid) unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("authenticateUser(valid) = false, want true")
	}

	ok, err = authenticateUser("admin", "wrong")
	if err != nil {
		t.Fatalf("authenticateUser(invalid) unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("authenticateUser(invalid) = true, want false")
	}
	ok, err = authenticateUser("ghost", "anything")
	if err != nil {
		t.Fatalf("authenticateUser(non-existent user) unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("authenticateUser(non-existent user) = true, want false")
	}

	if err := createInitialUser("second", testPasswordAlt); err == nil {
		t.Fatalf("createInitialUser(second) error = nil, want errSetupAlreadyCompleted")
	}
}

func TestMetricsBearerMiddleware(t *testing.T) {
	preserveDBState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "metrics-middleware.db"))
	_ = getDB()

	if err := clearMetricsBearerTokenHash(); err != nil {
		t.Fatalf("clearMetricsBearerTokenHash() unexpected error: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(metricsBearerMiddleware())
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	disabledReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	disabledRec := httptest.NewRecorder()
	r.ServeHTTP(disabledRec, disabledReq)
	if disabledRec.Code != http.StatusNotFound {
		t.Fatalf("disabled metrics status = %d, want %d", disabledRec.Code, http.StatusNotFound)
	}

	token, err := issueMetricsBearerToken()
	if err != nil {
		t.Fatalf("issueMetricsBearerToken() unexpected error: %v", err)
	}

	cases := []struct {
		name         string
		authz        string
		wantHTTPCode int
	}{
		{name: "missing token", authz: "", wantHTTPCode: http.StatusUnauthorized},
		{name: "wrong scheme", authz: "Basic abc", wantHTTPCode: http.StatusUnauthorized},
		{name: "wrong token", authz: "Bearer nope", wantHTTPCode: http.StatusUnauthorized},
		{name: "valid token", authz: "Bearer " + token, wantHTTPCode: http.StatusOK},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.authz != "" {
				req.Header.Set("Authorization", tc.authz)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tc.wantHTTPCode {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.wantHTTPCode, rec.Body.String())
			}
		})
	}

	// Use a tiny threshold so this test can deterministically assert 429 behavior.
	testMetrics := NewAuthRateLimiter(metricsRateLimitWindow, 2)
	prevMetrics := metricsRateLimiter
	metricsRateLimiter = testMetrics
	t.Cleanup(func() {
		testMetrics.Stop()
		metricsRateLimiter = prevMetrics
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("rate-limit setup request %d status = %d, want %d", i+1, rec.Code, http.StatusOK)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limit status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

func TestMetricsBearerTokenLifecycle(t *testing.T) {
	preserveDBState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "metrics-token-lifecycle.db"))
	_ = getDB()

	if err := clearMetricsBearerTokenHash(); err != nil {
		t.Fatalf("clearMetricsBearerTokenHash() unexpected error: %v", err)
	}
	if got := getMetricsBearerTokenHash(); got != "" {
		t.Fatalf("getMetricsBearerTokenHash() = %q, want empty", got)
	}

	token, err := issueMetricsBearerToken()
	if err != nil {
		t.Fatalf("issueMetricsBearerToken() unexpected error: %v", err)
	}
	if token == "" {
		t.Fatalf("issueMetricsBearerToken() token is empty")
	}
	if _, err := base64.RawURLEncoding.DecodeString(token); err != nil {
		t.Fatalf("issueMetricsBearerToken() token is not valid base64url: %v", err)
	}

	tokenHash := getMetricsBearerTokenHash()
	if tokenHash == "" {
		t.Fatalf("getMetricsBearerTokenHash() empty after issue")
	}
	match, err := argon2id.ComparePasswordAndHash(token, tokenHash)
	if err != nil {
		t.Fatalf("ComparePasswordAndHash() unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("ComparePasswordAndHash() = false, want true")
	}

	if err := clearMetricsBearerTokenHash(); err != nil {
		t.Fatalf("clearMetricsBearerTokenHash() unexpected error: %v", err)
	}
	if got := getMetricsBearerTokenHash(); got != "" {
		t.Fatalf("getMetricsBearerTokenHash() = %q after clear, want empty", got)
	}
}

func TestAuthSetupLoginLogoutAndGate(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "auth-flow.db"))

	sm, err := newSessionManager(getDB())
	if err != nil {
		t.Fatalf("newSessionManager() unexpected error: %v", err)
	}
	sessionManager = sm

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/setup", handleSetupPage)
	r.GET("/login", handleLoginPage)
	r.POST("/api/auth/setup", handleAuthSetup)
	r.POST("/api/auth/login", handleAuthLogin)
	r.GET("/api/auth/status", handleAuthStatus)
	r.Use(authGateMiddleware())
	r.POST("/api/auth/logout", handleAuthLogout)
	r.GET("/api/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "actor": actorFromContext(c)})
	})
	r.GET("/page", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	handler := sessionManager.LoadAndSave(r)
	var setupCookie *http.Cookie
	var loginCookie *http.Cookie

	t.Run("unauthenticated API ping/status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated API status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if !strings.Contains(rec.Body.String(), `"setup_required":true`) {
			t.Fatalf("unauthenticated API body missing setup_required=true: %s", rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("auth status before setup status = %d, want %d", rec.Code, http.StatusOK)
		}
		var statusPayload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &statusPayload); err != nil {
			t.Fatalf("auth status before setup unmarshal error = %v", err)
		}
		if got, _ := statusPayload["setup_required"].(bool); !got {
			t.Fatalf("auth status before setup setup_required = %v, want true", statusPayload["setup_required"])
		}
		if got, _ := statusPayload["authenticated"].(bool); got {
			t.Fatalf("auth status before setup authenticated = %v, want false", statusPayload["authenticated"])
		}
	})

	t.Run("unauthenticated HTML redirect", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/page", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("unauthenticated HTML status = %d, want %d", rec.Code, http.StatusFound)
		}
		if got := rec.Header().Get("Location"); got != "/setup" {
			t.Fatalf("unauthenticated HTML redirect = %q, want %q", got, "/setup")
		}
	})

	t.Run("setup", func(t *testing.T) {
		setupBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", setupBody)
		markSameOriginAuthRequest(req)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("setup status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
		}
		setupCookie = testSessionCookieFromRecorder(t, rec)
	})

	t.Run("post-setup authenticated API", func(t *testing.T) {
		if setupCookie == nil {
			t.Fatalf("setup cookie is nil")
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
		req.AddCookie(setupCookie)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("authenticated API status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"actor":"admin"`) {
			t.Fatalf("authenticated API body missing actor admin: %s", rec.Body.String())
		}
	})

	t.Run("logout", func(t *testing.T) {
		if setupCookie == nil {
			t.Fatalf("setup cookie is nil")
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		markSameOriginAuthRequest(req)
		req.AddCookie(setupCookie)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("logout status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("post-logout API", func(t *testing.T) {
		if setupCookie == nil {
			t.Fatalf("setup cookie is nil")
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
		req.AddCookie(setupCookie)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("API status after logout = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if !strings.Contains(rec.Body.String(), `"setup_required":false`) {
			t.Fatalf("post-logout API body missing setup_required=false: %s", rec.Body.String())
		}
	})

	t.Run("invalid login", func(t *testing.T) {
		loginBody := bytes.NewBufferString(`{"username":"admin","password":"wrong-pass"}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody)
		markSameOriginAuthRequest(req)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("login invalid status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("valid login and status", func(t *testing.T) {
		loginBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody)
		markSameOriginAuthRequest(req)
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("login valid status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
		}
		loginCookie = testSessionCookieFromRecorder(t, rec)

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/page", nil)
		req.AddCookie(loginCookie)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("authenticated HTML status = %d, want %d", rec.Code, http.StatusOK)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
		req.AddCookie(loginCookie)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("auth status after login status = %d, want %d", rec.Code, http.StatusOK)
		}
		var statusPayload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &statusPayload); err != nil {
			t.Fatalf("auth status after login unmarshal error = %v", err)
		}
		if got, _ := statusPayload["authenticated"].(bool); !got {
			t.Fatalf("auth status after login authenticated = %v, want true", statusPayload["authenticated"])
		}
		if got, _ := statusPayload["username"].(string); got != "admin" {
			t.Fatalf("auth status after login username = %q, want %q", got, "admin")
		}
	})
}

func TestAuthEndpointsAllowMissingSecFetchSite(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "auth-missing-sec-fetch.db"))

	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(r)

	setupBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
	setupRec := httptest.NewRecorder()
	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", setupBody)
	markSameOriginAuthRequestWithoutSecFetch(setupReq)
	setupReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", setupRec.Code, http.StatusOK, setupRec.Body.String())
	}
	sessionCookie := testSessionCookieFromRecorder(t, setupRec)

	logoutRec := httptest.NewRecorder()
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	markSameOriginAuthRequestWithoutSecFetch(logoutReq)
	logoutReq.AddCookie(sessionCookie)
	handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want %d (body=%s)", logoutRec.Code, http.StatusOK, logoutRec.Body.String())
	}

	loginBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody)
	markSameOriginAuthRequestWithoutSecFetch(loginReq)
	loginReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d (body=%s)", loginRec.Code, http.StatusOK, loginRec.Body.String())
	}
}

func TestAuthSetupRejectsMismatchedOriginAndInvalidSecFetchSite(t *testing.T) {
	t.Run("rejects mismatched origin host", func(t *testing.T) {
		preserveDBState(t)
		preserveSessionState(t)
		preserveRateLimiterState(t)
		preserveMetricsTokenState(t)
		t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "auth-origin-mismatch.db"))

		r, err := setupRouter()
		if err != nil {
			t.Fatalf("setupRouter() unexpected error: %v", err)
		}
		handler := sessionManager.LoadAndSave(r)

		body := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", body)
		req.Host = "localhost"
		req.Header.Set("Origin", "http://evil.local")
		req.Header.Set("Referer", "http://localhost/setup")
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusForbidden, rec.Body.String())
		}
	})

	t.Run("rejects invalid Sec-Fetch-Site when present", func(t *testing.T) {
		preserveDBState(t)
		preserveSessionState(t)
		preserveRateLimiterState(t)
		preserveMetricsTokenState(t)
		t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "auth-sec-fetch-invalid.db"))

		r, err := setupRouter()
		if err != nil {
			t.Fatalf("setupRouter() unexpected error: %v", err)
		}
		handler := sessionManager.LoadAndSave(r)

		body := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", body)
		req.Host = "localhost"
		req.Header.Set("Origin", "http://localhost")
		req.Header.Set("Referer", "http://localhost/setup")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusForbidden, rec.Body.String())
		}
	})
}

func TestMetricsTokenAPIAndMetricsRouteLifecycle(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "metrics-router-lifecycle.db"))

	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("metrics before token status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	setupBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/setup", setupBody)
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	sessionCookie := testSessionCookieFromRecorder(t, rec)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/metrics/token", nil)
	req.AddCookie(sessionCookie)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics token status before create = %d, want %d", rec.Code, http.StatusOK)
	}
	var statusPayload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &statusPayload); err != nil {
		t.Fatalf("metrics token status before create unmarshal error = %v", err)
	}
	if enabled, _ := statusPayload["enabled"].(bool); enabled {
		t.Fatalf("metrics token status enabled = true before create, want false")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/metrics/token", nil)
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics token create status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var createPayload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &createPayload); err != nil {
		t.Fatalf("metrics token create unmarshal error = %v", err)
	}
	firstToken, _ := createPayload["token"].(string)
	if strings.TrimSpace(firstToken) == "" {
		t.Fatalf("metrics token create token empty")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+firstToken)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics with first token status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/metrics/token", nil)
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics token rotate status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	createPayload = map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &createPayload); err != nil {
		t.Fatalf("metrics token rotate unmarshal error = %v", err)
	}
	secondToken, _ := createPayload["token"].(string)
	if strings.TrimSpace(secondToken) == "" {
		t.Fatalf("metrics token rotate token empty")
	}
	if secondToken == firstToken {
		t.Fatalf("metrics token rotate returned same token")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+firstToken)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics with old token status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+secondToken)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics with rotated token status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/metrics/token", nil)
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics token clear status = %d, want %d", rec.Code, http.StatusOK)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/audit-events?page=1&page_size=50", nil)
	req.AddCookie(sessionCookie)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit events status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); strings.Contains(body, firstToken) || strings.Contains(body, secondToken) {
		t.Fatalf("audit payload unexpectedly contains metrics token")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+secondToken)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("metrics after clear status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "security-headers.db"))

	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(r)

	t.Run("http response has hardening headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("auth status code = %d, want %d", rec.Code, http.StatusOK)
		}
		assertSecurityHeaders(t, rec.Header(), false)
	})

	t.Run("https response sets HSTS", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
		req.TLS = &tls.ConnectionState{}
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("auth status code = %d, want %d", rec.Code, http.StatusOK)
		}
		assertSecurityHeaders(t, rec.Header(), true)
	})

	t.Run("forwarded https sets HSTS", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("auth status code = %d, want %d", rec.Code, http.StatusOK)
		}
		assertSecurityHeaders(t, rec.Header(), true)
	})
}

func TestAuthGateAllowsStaticAssetsUnauthenticated(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "auth-gate-static.db"))

	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/auth.js", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("static asset status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ctype := rec.Header().Get("Content-Type"); !strings.Contains(ctype, "javascript") {
		t.Fatalf("static asset content-type = %q, want javascript", ctype)
	}
}
