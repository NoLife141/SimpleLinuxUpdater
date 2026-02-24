package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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

	testLogin := NewAuthRateLimiter(authRateLimitWindow, authLoginRateLimitMaxAttempts)
	testSetup := NewAuthRateLimiter(authRateLimitWindow, authSetupRateLimitMaxAttempts)
	loginRateLimiter = testLogin
	setupRateLimiter = testSetup

	t.Cleanup(func() {
		testLogin.Stop()
		testSetup.Stop()
		loginRateLimiter = origLogin
		setupRateLimiter = origSetup
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

func TestValidatePasswordPolicy(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "empty string", value: "", wantErr: true},
		{name: "too short", value: "Abc123", wantErr: true},
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
	t.Setenv(metricsBearerTokenEnv, "change-me-metrics-token")
	if _, err := metricsBearerTokenFromEnv(); err == nil {
		t.Fatalf("metricsBearerTokenFromEnv() error = nil, want error for placeholder token")
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
	preserveRateLimiterState(t)
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

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/page", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("unauthenticated HTML status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != "/setup" {
		t.Fatalf("unauthenticated HTML redirect = %q, want %q", got, "/setup")
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
	markSameOriginAuthRequest(req)
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
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("login invalid status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	loginBody = bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody)
	markSameOriginAuthRequest(req)
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
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.AddCookie(loginCookie)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("auth status after login status = %d, want %d", rec.Code, http.StatusOK)
	}
	statusPayload = map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &statusPayload); err != nil {
		t.Fatalf("auth status after login unmarshal error = %v", err)
	}
	if got, _ := statusPayload["authenticated"].(bool); !got {
		t.Fatalf("auth status after login authenticated = %v, want true", statusPayload["authenticated"])
	}
	if got, _ := statusPayload["username"].(string); got != "admin" {
		t.Fatalf("auth status after login username = %q, want %q", got, "admin")
	}
}
