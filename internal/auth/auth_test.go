package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

const testPassword = "StrongPass123"

func TestValidatePasswordPolicyAndUsername(t *testing.T) {
	passwordTests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid", value: testPassword},
		{name: "too short", value: "Short1", wantErr: true},
		{name: "missing digit", value: "StrongPassword", wantErr: true},
		{name: "missing letter", value: "1234567890", wantErr: true},
		{name: "too long", value: strings.Repeat("A", MaxPasswordLen) + "1", wantErr: true},
	}
	for _, tt := range passwordTests {
		t.Run("password "+tt.name, func(t *testing.T) {
			err := ValidatePasswordPolicy(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePasswordPolicy(%q) err=%v, wantErr=%v", tt.value, err, tt.wantErr)
			}
		})
	}

	usernameTests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid", value: "admin.user-1"},
		{name: "empty", value: " ", wantErr: true},
		{name: "too long", value: strings.Repeat("a", 65), wantErr: true},
		{name: "invalid char", value: "admin/user", wantErr: true},
	}
	for _, tt := range usernameTests {
		t.Run("username "+tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateUsername(%q) err=%v, wantErr=%v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestServiceSingleUserLifecycle(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(ServiceOptions{
		DB: func() *sql.DB { return db },
		Now: func() time.Time {
			return time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
		},
	})
	required, err := svc.SetupRequired()
	if err != nil {
		t.Fatalf("SetupRequired() error = %v", err)
	}
	if !required {
		t.Fatalf("SetupRequired() = false, want true")
	}
	if ok, err := svc.Authenticate("admin", testPassword); ok || err != ErrSetupRequired {
		t.Fatalf("Authenticate(before setup) = %v, %v, want false/%v", ok, err, ErrSetupRequired)
	}
	if err := svc.CreateInitialUser("admin", testPassword); err != nil {
		t.Fatalf("CreateInitialUser() error = %v", err)
	}
	if err := svc.CreateInitialUser("second", testPassword); err != ErrSetupAlreadyCompleted {
		t.Fatalf("CreateInitialUser(second) error = %v, want %v", err, ErrSetupAlreadyCompleted)
	}
	if ok, err := svc.Authenticate("admin", testPassword); err != nil || !ok {
		t.Fatalf("Authenticate(valid) = %v, %v, want true/nil", ok, err)
	}
	if ok, err := svc.Authenticate("admin", "wrong"); err != nil || ok {
		t.Fatalf("Authenticate(wrong) = %v, %v, want false/nil", ok, err)
	}
	if err := svc.ChangePassword(testPassword, "NewStrongPass123", "NewStrongPass123"); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}
	if ok, err := svc.Authenticate("admin", "NewStrongPass123"); err != nil || !ok {
		t.Fatalf("Authenticate(new password) = %v, %v, want true/nil", ok, err)
	}
}

func TestServiceSessionCountAndClear(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.Exec("INSERT INTO sessions(token, data, expiry) VALUES('one', x'00', '2026-05-18T12:00:00Z')"); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	svc := NewService(ServiceOptions{DB: func() *sql.DB { return db }})
	count, err := svc.CountSessions()
	if err != nil {
		t.Fatalf("CountSessions() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("CountSessions() = %d, want 1", count)
	}
	deleted, err := svc.ClearSessions()
	if err != nil {
		t.Fatalf("ClearSessions() error = %v", err)
	}
	if deleted != 1 {
		t.Fatalf("ClearSessions() = %d, want 1", deleted)
	}
}

func TestNewSessionManagerPreservesCookieOptions(t *testing.T) {
	db := newTestDB(t)
	t.Setenv(SessionCookieSecureEnv, "true")
	t.Setenv(SessionIdleTimeoutHoursEnv, "2")
	sm, err := NewSessionManager(db, SessionManagerOptions{})
	if err != nil {
		t.Fatalf("NewSessionManager() error = %v", err)
	}
	if sm.Cookie.Name != DefaultSessionCookieName || !sm.Cookie.HttpOnly || !sm.Cookie.Secure || !sm.Cookie.Persist || sm.Cookie.Path != "/" {
		t.Fatalf("unexpected cookie options: %+v", sm.Cookie)
	}
	if sm.IdleTimeout != 2*time.Hour {
		t.Fatalf("IdleTimeout = %s, want 2h", sm.IdleTimeout)
	}
}

func TestRateLimiterAllowLimitedAndRecordFailure(t *testing.T) {
	limiter := NewRateLimiter(time.Minute, 2)
	defer limiter.Stop()
	if !limiter.Allow("client") {
		t.Fatalf("first Allow() = false, want true")
	}
	if !limiter.Allow("client") {
		t.Fatalf("second Allow() = false, want true")
	}
	if limiter.Allow("client") {
		t.Fatalf("third Allow() = true, want false")
	}
	other := NewRateLimiter(time.Minute, 2)
	defer other.Stop()
	other.RecordFailure("client")
	other.RecordFailure("client")
	if !other.Limited("client") {
		t.Fatalf("Limited() = false, want true after recorded failures")
	}
}

func TestSameOriginRequestAndWriteMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost")
	req.Header.Set("Referer", "http://localhost/")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	ctx.Request = req
	if !SameOriginRequest(ctx) {
		t.Fatalf("SameOriginRequest() = false, want true")
	}

	router := gin.New()
	router.Use(SameOriginWriteMiddleware())
	router.POST("/write", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	blockedRec := httptest.NewRecorder()
	blockedReq := httptest.NewRequest(http.MethodPost, "/write", nil)
	blockedReq.Host = "localhost"
	router.ServeHTTP(blockedRec, blockedReq)
	if blockedRec.Code != http.StatusForbidden {
		t.Fatalf("blocked status = %d, want %d", blockedRec.Code, http.StatusForbidden)
	}
}

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ensureTestSchema(t, db)
	return db
}

func ensureTestSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS auth_users (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("create auth_users schema: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		data BLOB NOT NULL,
		expiry TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("create sessions schema: %v", err)
	}
}
