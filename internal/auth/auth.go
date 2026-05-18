package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/alexedwards/argon2id"
	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
	"github.com/gin-gonic/gin"
)

const (
	SessionCookieSecureEnv        = "DEBIAN_UPDATER_SESSION_COOKIE_SECURE"
	SessionIdleTimeoutHoursEnv    = "DEBIAN_UPDATER_SESSION_IDLE_TIMEOUT_HOURS"
	SessionUserKey                = "auth_user"
	UserID                        = 1
	MinPasswordLen                = 10
	MaxPasswordLen                = 64
	MaxRequestBytes               = 8 * 1024
	LoginRateLimitMaxAttempts     = 10
	PasswordChangeMaxAttempts     = 5
	SetupRateLimitMaxAttempts     = 5
	MetricsRateLimitMaxAttempts   = 120
	RateLimitWindow               = 10 * time.Minute
	MetricsRateLimitWindow        = time.Minute
	DefaultSessionLifetime        = 30 * 24 * time.Hour
	DefaultSessionCookieName      = "simplelinuxupdater_session"
	defaultRateLimitCleanupWindow = time.Minute
)

var (
	ErrSetupAlreadyCompleted = errors.New("setup already completed")
	ErrSetupRequired         = errors.New("setup required")
	ErrPasswordMismatch      = errors.New("password confirmation does not match")
)

type CredentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

type RateBucket struct {
	attempts  int
	windowEnd time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	buckets map[string]RateBucket
	stopCh  chan struct{}
	doneCh  chan struct{}
	stopMu  sync.Mutex
	stopped bool
}

func NewRateLimiter(window time.Duration, max int) *RateLimiter {
	if window <= 0 {
		window = RateLimitWindow
	}
	limiter := &RateLimiter{
		window:  window,
		max:     max,
		buckets: make(map[string]RateBucket),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
	cleanupInterval := window / 2
	if cleanupInterval < defaultRateLimitCleanupWindow {
		cleanupInterval = defaultRateLimitCleanupWindow
	}
	go limiter.cleanupWorker(cleanupInterval)
	return limiter
}

func (l *RateLimiter) cleanupExpiredLocked(now time.Time) {
	for key, bucket := range l.buckets {
		if now.After(bucket.windowEnd) {
			delete(l.buckets, key)
		}
	}
}

func (l *RateLimiter) cleanupWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(l.doneCh)
	for {
		select {
		case <-l.stopCh:
			return
		case now := <-ticker.C:
			l.mu.Lock()
			l.cleanupExpiredLocked(now)
			l.mu.Unlock()
		}
	}
}

func (l *RateLimiter) Stop() {
	l.stopMu.Lock()
	if l.stopped {
		l.stopMu.Unlock()
		return
	}
	l.stopped = true
	close(l.stopCh)
	l.stopMu.Unlock()
	<-l.doneCh
}

func (l *RateLimiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.buckets[key]
	if ok && now.After(bucket.windowEnd) {
		delete(l.buckets, key)
		ok = false
	}
	if !ok {
		l.buckets[key] = RateBucket{
			attempts:  1,
			windowEnd: now.Add(l.window),
		}
		return true
	}
	if bucket.attempts >= l.max {
		return false
	}
	bucket.attempts++
	l.buckets[key] = bucket
	return true
}

func (l *RateLimiter) Limited(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.buckets[key]
	if ok && now.After(bucket.windowEnd) {
		delete(l.buckets, key)
		return false
	}
	return ok && bucket.attempts >= l.max
}

func (l *RateLimiter) RecordFailure(key string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.buckets[key]
	if ok && now.After(bucket.windowEnd) {
		delete(l.buckets, key)
		ok = false
	}
	if !ok {
		l.buckets[key] = RateBucket{
			attempts:  1,
			windowEnd: now.Add(l.window),
		}
		return
	}
	bucket.attempts++
	l.buckets[key] = bucket
}

type DBProvider func() *sql.DB

type User struct {
	Username     string
	PasswordHash string
}

type Repository interface {
	SetupRequired() (bool, error)
	GetSingleUser() (User, bool, error)
	CreateInitialUser(username, passwordHash, now string) error
	UpdatePasswordHash(passwordHash, now string) error
	CountSessions() (int, error)
	ClearSessions() (int64, error)
}

type SQLiteRepository struct {
	db DBProvider
}

func NewSQLiteRepository(db DBProvider) *SQLiteRepository {
	return &SQLiteRepository{db: db}
}

func (r *SQLiteRepository) SetupRequired() (bool, error) {
	var count int
	err := r.db().QueryRow("SELECT COUNT(1) FROM auth_users").Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func (r *SQLiteRepository) GetSingleUser() (User, bool, error) {
	var user User
	err := r.db().QueryRow("SELECT username, password_hash FROM auth_users WHERE id = ?", UserID).Scan(&user.Username, &user.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return user, true, nil
}

func (r *SQLiteRepository) CreateInitialUser(username, passwordHash, now string) error {
	tx, err := r.db().BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRow("SELECT COUNT(1) FROM auth_users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return ErrSetupAlreadyCompleted
	}
	if _, err := tx.Exec(
		"INSERT INTO auth_users(id, username, password_hash, created_at, updated_at) VALUES(?, ?, ?, ?, ?)",
		UserID, username, passwordHash, now, now,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SQLiteRepository) UpdatePasswordHash(passwordHash, now string) error {
	_, err := r.db().Exec(
		"UPDATE auth_users SET password_hash = ?, updated_at = ? WHERE id = ?",
		passwordHash,
		now,
		UserID,
	)
	return err
}

func (r *SQLiteRepository) CountSessions() (int, error) {
	var count int
	err := r.db().QueryRow("SELECT COUNT(1) FROM sessions").Scan(&count)
	return count, err
}

func (r *SQLiteRepository) ClearSessions() (int64, error) {
	result, err := r.db().Exec("DELETE FROM sessions")
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return rows, nil
}

type ServiceOptions struct {
	DB   DBProvider
	Repo Repository
	Now  func() time.Time
}

type Service struct {
	repo Repository
	now  func() time.Time
}

func NewService(opts ServiceOptions) *Service {
	if opts.DB == nil {
		opts.DB = func() *sql.DB { return nil }
	}
	if opts.Repo == nil {
		opts.Repo = NewSQLiteRepository(opts.DB)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{repo: opts.Repo, now: opts.Now}
}

func (s *Service) SetupRequired() (bool, error) {
	return s.repo.SetupRequired()
}

func (s *Service) GetSingleUser() (username, passwordHash string, exists bool, err error) {
	user, exists, err := s.repo.GetSingleUser()
	if err != nil || !exists {
		return "", "", exists, err
	}
	return user.Username, user.PasswordHash, true, nil
}

func (s *Service) ValidatePasswordPolicy(password string) error {
	return ValidatePasswordPolicy(password)
}

func (s *Service) ValidateUsername(username string) error {
	return ValidateUsername(username)
}

func (s *Service) CreateInitialUser(username, password string) error {
	username = strings.TrimSpace(username)
	if err := s.ValidateUsername(username); err != nil {
		return err
	}
	if err := s.ValidatePasswordPolicy(password); err != nil {
		return err
	}

	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return err
	}

	now := s.now().UTC().Format(time.RFC3339)
	return s.repo.CreateInitialUser(username, hash, now)
}

func (s *Service) Authenticate(username, password string) (bool, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return false, nil
	}
	storedUsername, storedHash, exists, err := s.GetSingleUser()
	if err != nil {
		return false, err
	}
	if !exists {
		return false, ErrSetupRequired
	}
	usernameMatch := stringsEqualConstantTime(username, storedUsername)
	match, err := argon2id.ComparePasswordAndHash(password, storedHash)
	if err != nil {
		return false, err
	}
	if !usernameMatch {
		return false, nil
	}
	return match, nil
}

func (s *Service) ChangePassword(currentPassword, newPassword, confirmPassword string) error {
	if newPassword != confirmPassword {
		return ErrPasswordMismatch
	}
	storedUsername, _, exists, err := s.GetSingleUser()
	if err != nil {
		return err
	}
	if !exists {
		return ErrSetupRequired
	}
	ok, err := s.Authenticate(storedUsername, currentPassword)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("current password is invalid")
	}
	if err := s.ValidatePasswordPolicy(newPassword); err != nil {
		return err
	}
	hash, err := argon2id.CreateHash(newPassword, argon2id.DefaultParams)
	if err != nil {
		return err
	}
	now := s.now().UTC().Format(time.RFC3339)
	return s.repo.UpdatePasswordHash(hash, now)
}

func (s *Service) CountSessions() (int, error) {
	return s.repo.CountSessions()
}

func (s *Service) ClearSessions() (int64, error) {
	return s.repo.ClearSessions()
}

func ValidatePasswordPolicy(password string) error {
	passwordLen := utf8.RuneCountInString(password)
	if passwordLen < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters long", MinPasswordLen)
	}
	if passwordLen > MaxPasswordLen {
		return fmt.Errorf("password must be %d characters or less", MaxPasswordLen)
	}
	hasLetter := false
	hasDigit := false
	for _, r := range password {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
		}
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return errors.New("password must include at least one letter and one digit")
	}
	return nil
}

func ValidateUsername(username string) error {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return errors.New("username is required")
	}
	if len(trimmed) > 64 {
		return errors.New("username must be 64 characters or less")
	}
	if !isValidUsername(trimmed) {
		return errors.New("username contains unsupported characters")
	}
	return nil
}

func isValidUsername(username string) bool {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" || len(trimmed) > 64 {
		return false
	}
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func stringsEqualConstantTime(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type SessionManagerOptions struct {
	SecureCookieEnv     string
	IdleTimeoutHoursEnv string
	CookieName          string
	Lifetime            time.Duration
	Logf                func(string, ...any)
}

func NewSessionManager(db *sql.DB, opts SessionManagerOptions) (*scs.SessionManager, error) {
	secureEnv := strings.TrimSpace(opts.SecureCookieEnv)
	if secureEnv == "" {
		secureEnv = SessionCookieSecureEnv
	}
	idleTimeoutEnv := strings.TrimSpace(opts.IdleTimeoutHoursEnv)
	if idleTimeoutEnv == "" {
		idleTimeoutEnv = SessionIdleTimeoutHoursEnv
	}
	cookieName := strings.TrimSpace(opts.CookieName)
	if cookieName == "" {
		cookieName = DefaultSessionCookieName
	}
	lifetime := opts.Lifetime
	if lifetime <= 0 {
		lifetime = DefaultSessionLifetime
	}
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}

	secureCookie, err := parseBoolEnv(secureEnv, false)
	if err != nil {
		return nil, err
	}
	if !secureCookie {
		logf("%s=false; session cookie Secure flag is disabled (acceptable for local HTTP only). Set true behind HTTPS.", secureEnv)
	}
	idleTimeout, err := parseSessionIdleTimeout(idleTimeoutEnv)
	if err != nil {
		return nil, err
	}

	sm := scs.New()
	sm.Store = sqlite3store.New(db)
	sm.Lifetime = lifetime
	sm.Cookie.Name = cookieName
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode
	sm.Cookie.Secure = secureCookie
	sm.Cookie.Persist = true
	sm.Cookie.Path = "/"
	if idleTimeout > 0 {
		sm.IdleTimeout = idleTimeout
	}
	return sm, nil
}

func parseBoolEnv(name string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback, fmt.Errorf("%s must be a boolean value: %w", name, err)
	}
	return v, nil
}

func parseSessionIdleTimeout(name string) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, nil
	}
	hours, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer number of hours: %w", name, err)
	}
	if hours < 0 {
		return 0, fmt.Errorf("%s must be >= 0", name)
	}
	if hours == 0 {
		return 0, nil
	}
	return time.Duration(hours) * time.Hour, nil
}

func SessionUsername(c *gin.Context, sm *scs.SessionManager) string {
	if c == nil || sm == nil {
		return ""
	}
	return strings.TrimSpace(sm.GetString(c.Request.Context(), SessionUserKey))
}

func SameOriginRequest(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(c.Request.Host))
	if host == "" {
		return false
	}
	origin := strings.TrimSpace(c.GetHeader("Origin"))
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		if !stringsEqualConstantTime(strings.ToLower(u.Host), host) {
			return false
		}
	}
	referer := strings.TrimSpace(c.GetHeader("Referer"))
	if referer != "" {
		u, err := url.Parse(referer)
		if err != nil {
			return false
		}
		if !stringsEqualConstantTime(strings.ToLower(u.Host), host) {
			return false
		}
	}
	if origin == "" && referer == "" {
		return false
	}
	secFetchSite := strings.ToLower(strings.TrimSpace(c.GetHeader("Sec-Fetch-Site")))
	if secFetchSite != "" && secFetchSite != "same-origin" && secFetchSite != "same-site" {
		return false
	}
	return true
}

func SameOriginWriteMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		if !SameOriginRequest(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-site write request denied"})
			return
		}
		c.Next()
	}
}
