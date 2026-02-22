package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func preserveSessionState(t *testing.T) {
	t.Helper()
	orig := sessionManager
	t.Cleanup(func() {
		sessionManager = orig
	})
}

func testSessionCookieFromRecorder(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if sessionManager != nil && cookie.Name == sessionManager.Cookie.Name {
			return cookie
		}
	}
	t.Fatalf("session cookie %q not found in response", sessionManager.Cookie.Name)
	return nil
}

func TestSetupRequiredAndSingleUserLifecycle(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "auth-lifecycle.db"))
	t.Setenv("DEBIAN_UPDATER_DB_PATH", t.TempDir()+"/auth-session.db")

	required, err := setupRequired()
	if err != nil {
		t.Fatalf("setupRequired() unexpected error: %v", err)
	}
	if !required {
		t.Fatalf("setupRequired() = false, want true on empty auth_users")
	}

	if err := createInitialUser("admin", "StrongPass123"); err != nil {
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
	if passwordHash == "" || strings.Contains(passwordHash, "StrongPass123") {
		t.Fatalf("getSingleUser() password hash appears invalid: %q", passwordHash)
	}

	ok, err := authenticateUser("admin", "StrongPass123")
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

	if err := createInitialUser("second", "StrongPass999"); err == nil {
		t.Fatalf("createInitialUser(second) error = nil, want errSetupAlreadyCompleted")
	}
}

func TestMetricsBearerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(metricsBearerMiddleware("token-123"))
	r.GET("/metrics", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	cases := []struct {
		name         string
		authz        string
		wantHTTPCode int
	}{
		{name: "missing token", authz: "", wantHTTPCode: http.StatusUnauthorized},
		{name: "wrong scheme", authz: "Basic abc", wantHTTPCode: http.StatusUnauthorized},
		{name: "wrong token", authz: "Bearer nope", wantHTTPCode: http.StatusUnauthorized},
		{name: "valid token", authz: "Bearer token-123", wantHTTPCode: http.StatusOK},
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
}

func TestMetricsBearerTokenFromEnv(t *testing.T) {
	t.Setenv(metricsBearerTokenEnv, "")
	if _, err := metricsBearerTokenFromEnv(); err == nil {
		t.Fatalf("metricsBearerTokenFromEnv() error = nil, want error when token is missing")
	}

	t.Setenv(metricsBearerTokenEnv, " test-token ")
	token, err := metricsBearerTokenFromEnv()
	if err != nil {
		t.Fatalf("metricsBearerTokenFromEnv() unexpected error: %v", err)
	}
	if token != "test-token" {
		t.Fatalf("metricsBearerTokenFromEnv() = %q, want %q", token, "test-token")
	}
}

func TestAuthSetupLoginLogoutAndGate(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "auth-gate.db"))
	t.Setenv("DEBIAN_UPDATER_DB_PATH", t.TempDir()+"/auth-flow.db")

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
	req = httptest.NewRequest(http.MethodGet, "/page", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("unauthenticated HTML status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != "/setup" {
		t.Fatalf("unauthenticated HTML redirect = %q, want %q", got, "/setup")
	}

	setupBody := bytes.NewBufferString(`{"username":"admin","password":"StrongPass123"}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/setup", setupBody)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	setupCookie := testSessionCookieFromRecorder(t, rec)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req.AddCookie(setupCookie)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated API status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"actor":"admin"`) {
		t.Fatalf("authenticated API body missing actor admin: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(setupCookie)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want %d", rec.Code, http.StatusOK)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req.AddCookie(setupCookie)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("API status after logout = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Body.String(), `"setup_required":false`) {
		t.Fatalf("post-logout API body missing setup_required=false: %s", rec.Body.String())
	}

	loginBody := bytes.NewBufferString(`{"username":"admin","password":"wrong-pass"}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("login invalid status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	loginBody = bytes.NewBufferString(`{"username":"admin","password":"StrongPass123"}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login valid status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	loginCookie := testSessionCookieFromRecorder(t, rec)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/page", nil)
	req.AddCookie(loginCookie)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated HTML status = %d, want %d", rec.Code, http.StatusOK)
	}
}
