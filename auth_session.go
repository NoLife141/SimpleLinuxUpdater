package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
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
	sessionCookieSecureEnv        = "DEBIAN_UPDATER_SESSION_COOKIE_SECURE"
	sessionIdleTimeoutHoursEnv    = "DEBIAN_UPDATER_SESSION_IDLE_TIMEOUT_HOURS"
	authSessionUserKey            = "auth_user"
	authUserID                    = 1
	authMinPasswordLen            = 10
	authMaxPasswordLen            = 64
	authLoginRateLimitMaxAttempts = 10
	authSetupRateLimitMaxAttempts = 5
	metricsRateLimitMaxAttempts   = 120
	authRateLimitWindow           = 10 * time.Minute
	metricsRateLimitWindow        = time.Minute
	defaultSessionLifetime        = 30 * 24 * time.Hour
)

var sessionManager *scs.SessionManager
var sessionManagerMu sync.RWMutex

var (
	errSetupAlreadyCompleted = errors.New("setup already completed")
	errSetupRequired         = errors.New("setup required")
)

type AuthRateBucket struct {
	attempts  int
	windowEnd time.Time
}

type AuthRateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	buckets map[string]AuthRateBucket
	stopCh  chan struct{}
	doneCh  chan struct{}
	stopMu  sync.Mutex
	stopped bool
}

func NewAuthRateLimiter(window time.Duration, max int) *AuthRateLimiter {
	if window <= 0 {
		window = authRateLimitWindow
	}
	limiter := &AuthRateLimiter{
		window:  window,
		max:     max,
		buckets: make(map[string]AuthRateBucket),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
	cleanupInterval := window / 2
	if cleanupInterval < time.Minute {
		cleanupInterval = time.Minute
	}
	go limiter.cleanupWorker(cleanupInterval)
	return limiter
}

func (l *AuthRateLimiter) cleanupExpiredLocked(now time.Time) {
	for key, bucket := range l.buckets {
		if now.After(bucket.windowEnd) {
			delete(l.buckets, key)
		}
	}
}

func (l *AuthRateLimiter) cleanupWorker(interval time.Duration) {
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

func (l *AuthRateLimiter) Stop() {
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

func (l *AuthRateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.buckets[key]
	if ok && now.After(bucket.windowEnd) {
		delete(l.buckets, key)
		ok = false
	}
	if !ok {
		l.buckets[key] = AuthRateBucket{
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

var (
	loginRateLimiter   = NewAuthRateLimiter(authRateLimitWindow, authLoginRateLimitMaxAttempts)
	setupRateLimiter   = NewAuthRateLimiter(authRateLimitWindow, authSetupRateLimitMaxAttempts)
	metricsRateLimiter = NewAuthRateLimiter(metricsRateLimitWindow, metricsRateLimitMaxAttempts)
)

func StopAuthRateLimiters() {
	if loginRateLimiter != nil {
		loginRateLimiter.Stop()
	}
	if setupRateLimiter != nil {
		setupRateLimiter.Stop()
	}
	if metricsRateLimiter != nil {
		metricsRateLimiter.Stop()
	}
}

type AuthCredentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
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

func parseSessionIdleTimeout() (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(sessionIdleTimeoutHoursEnv))
	if raw == "" {
		return 0, nil
	}
	hours, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer number of hours: %w", sessionIdleTimeoutHoursEnv, err)
	}
	if hours < 0 {
		return 0, fmt.Errorf("%s must be >= 0", sessionIdleTimeoutHoursEnv)
	}
	if hours == 0 {
		return 0, nil
	}
	return time.Duration(hours) * time.Hour, nil
}

func newSessionManager(db *sql.DB) (*scs.SessionManager, error) {
	secureCookie, err := parseBoolEnv(sessionCookieSecureEnv, false)
	if err != nil {
		return nil, err
	}
	if !secureCookie {
		log.Printf("%s=false; session cookie Secure flag is disabled (acceptable for local HTTP only). Set true behind HTTPS.", sessionCookieSecureEnv)
	}
	idleTimeout, err := parseSessionIdleTimeout()
	if err != nil {
		return nil, err
	}

	sm := scs.New()
	sm.Store = sqlite3store.New(db)
	sm.Lifetime = defaultSessionLifetime
	sm.Cookie.Name = "simplelinuxupdater_session"
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

func sessionHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sm := currentSessionManager()
		if sm == nil {
			next.ServeHTTP(w, r)
			return
		}
		sm.LoadAndSave(next).ServeHTTP(w, r)
	})
}

func setupRequired() (bool, error) {
	db := getDB()
	var count int
	err := db.QueryRow("SELECT COUNT(1) FROM auth_users").Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func getSingleUser() (username, passwordHash string, exists bool, err error) {
	row := getDB().QueryRow("SELECT username, password_hash FROM auth_users WHERE id = ?", authUserID)
	err = row.Scan(&username, &passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return username, passwordHash, true, nil
}

func validatePasswordPolicy(password string) error {
	passwordLen := utf8.RuneCountInString(password)
	if passwordLen < authMinPasswordLen {
		return fmt.Errorf("password must be at least %d characters long", authMinPasswordLen)
	}
	if passwordLen > authMaxPasswordLen {
		return fmt.Errorf("password must be %d characters or less", authMaxPasswordLen)
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

func validateAuthUsername(username string) error {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return errors.New("username is required")
	}
	if len(trimmed) > 64 {
		return errors.New("username must be 64 characters or less")
	}
	if !isValidSSHUsername(trimmed) {
		return errors.New("username contains unsupported characters")
	}
	return nil
}

func createInitialUser(username, password string) error {
	username = strings.TrimSpace(username)
	if err := validateAuthUsername(username); err != nil {
		return err
	}
	if err := validatePasswordPolicy(password); err != nil {
		return err
	}

	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return err
	}

	db := getDB()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRow("SELECT COUNT(1) FROM auth_users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errSetupAlreadyCompleted
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(
		"INSERT INTO auth_users(id, username, password_hash, created_at, updated_at) VALUES(?, ?, ?, ?, ?)",
		authUserID, username, hash, now, now,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func authenticateUser(username, password string) (bool, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return false, nil
	}
	storedUsername, storedHash, exists, err := getSingleUser()
	if err != nil {
		return false, err
	}
	if !exists {
		return false, errSetupRequired
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

func sessionUsername(c *gin.Context) string {
	if c == nil {
		return ""
	}
	sm := currentSessionManager()
	if sm == nil {
		return ""
	}
	return strings.TrimSpace(sm.GetString(c.Request.Context(), authSessionUserKey))
}

func currentSessionManager() *scs.SessionManager {
	sessionManagerMu.RLock()
	defer sessionManagerMu.RUnlock()
	return sessionManager
}

func setNoStoreHeaders(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
}

// sameOriginAuthRequest requires setup/login/logout requests to provide matching
// Origin/Referer host headers. If Sec-Fetch-Site is present, it must indicate
// same-origin/site context.
//
//	Origin: http://localhost
//	Referer: http://localhost/
//	Sec-Fetch-Site: same-origin (optional)
func sameOriginAuthRequest(c *gin.Context) bool {
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

func sameOriginWriteMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		if !sameOriginAuthRequest(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "cross-site write request denied"})
			return
		}
		c.Next()
	}
}

func backupRestoreBarrierMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c == nil || c.Request == nil || c.Request.URL == nil {
			c.Next()
			return
		}
		path := c.Request.URL.Path
		if maintenanceBypassPath(path) {
			c.Next()
			return
		}
		if currentMaintenanceState().Active && !maintenanceExclusivePath(path) {
			writeMaintenanceBlockedResponse(c)
			return
		}
		if maintenanceExclusivePath(path) {
			backupRestoreMu.Lock()
			defer backupRestoreMu.Unlock()
			if currentMaintenanceState().Active {
				writeMaintenanceBlockedResponse(c)
				return
			}
			c.Next()
			return
		}
		backupRestoreMu.RLock()
		defer backupRestoreMu.RUnlock()
		if currentMaintenanceState().Active {
			writeMaintenanceBlockedResponse(c)
			return
		}
		c.Next()
	}
}

func rateLimitClientIP(c *gin.Context) string {
	if c == nil {
		return "unknown"
	}
	host := strings.TrimSpace(c.ClientIP())
	if host == "" {
		return "unknown"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func metricsBearerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenHash := strings.TrimSpace(getMetricsBearerTokenHash())
		if tokenHash == "" {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		if metricsRateLimiter != nil && !metricsRateLimiter.allow(rateLimitClientIP(c)) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
			return
		}

		authz := strings.TrimSpace(c.GetHeader("Authorization"))
		if authz == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		parts := strings.Fields(authz)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid bearer token"})
			return
		}
		match, err := argon2id.ComparePasswordAndHash(parts[1], tokenHash)
		if err != nil || !match {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid bearer token"})
			return
		}
		c.Next()
	}
}

func authGateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") {
			c.Next()
			return
		}
		username := sessionUsername(c)
		if username != "" {
			c.Set("actor", username)
			c.Next()
			return
		}
		required, err := setupRequired()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to evaluate auth setup state"})
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":          "authentication required",
				"setup_required": required,
			})
			return
		}
		target := "/login"
		if required {
			target = "/setup"
		}
		c.Redirect(http.StatusFound, target)
		c.Abort()
	}
}

func handleSetupPage(c *gin.Context) {
	setNoStoreHeaders(c)
	required, err := setupRequired()
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to evaluate setup state")
		return
	}
	if !required {
		if sessionUsername(c) != "" {
			c.Redirect(http.StatusFound, "/")
		} else {
			c.Redirect(http.StatusFound, "/login")
		}
		return
	}
	c.HTML(http.StatusOK, "setup.html", nil)
}

func handleLoginPage(c *gin.Context) {
	setNoStoreHeaders(c)
	required, err := setupRequired()
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to evaluate setup state")
		return
	}
	if required {
		c.Redirect(http.StatusFound, "/setup")
		return
	}
	if sessionUsername(c) != "" {
		c.Redirect(http.StatusFound, "/")
		return
	}
	c.HTML(http.StatusOK, "login.html", nil)
}

func handleAuthStatus(c *gin.Context) {
	required, err := setupRequired()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to evaluate setup state"})
		return
	}
	username := sessionUsername(c)
	c.JSON(http.StatusOK, gin.H{
		"authenticated":  username != "",
		"username":       username,
		"setup_required": required,
	})
}

func handleAuthSetup(c *gin.Context) {
	if !sameOriginAuthRequest(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "cross-site setup request denied"})
		return
	}
	key := fmt.Sprintf("%s:setup", rateLimitClientIP(c))
	if !setupRateLimiter.allow(key) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many setup attempts"})
		return
	}
	required, err := setupRequired()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to evaluate setup state"})
		return
	}
	if !required {
		c.JSON(http.StatusConflict, gin.H{"error": "setup already completed"})
		return
	}

	var req AuthCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}
	username := strings.TrimSpace(req.Username)
	password := req.Password
	if err := validateAuthUsername(username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validatePasswordPolicy(password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := createInitialUser(username, password); err != nil {
		switch {
		case errors.Is(err, errSetupAlreadyCompleted):
			c.JSON(http.StatusConflict, gin.H{"error": "setup already completed"})
		default:
			log.Printf("handleAuthSetup: failed to create initial user for username=%q: %v", username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		}
		return
	}

	sm := currentSessionManager()
	if sm == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session manager not initialized"})
		return
	}
	if err := sm.RenewToken(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initialize session"})
		return
	}
	sm.Put(c.Request.Context(), authSessionUserKey, username)
	c.Set("actor", username)
	audit(c, "auth.setup", "auth_user", username, "success", "Initial admin user created", nil)
	c.JSON(http.StatusOK, gin.H{"message": "setup complete"})
}

func handleAuthLogin(c *gin.Context) {
	if !sameOriginAuthRequest(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "cross-site login request denied"})
		return
	}
	key := fmt.Sprintf("%s:login", rateLimitClientIP(c))
	if !loginRateLimiter.allow(key) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many login attempts"})
		return
	}
	required, err := setupRequired()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to evaluate setup state"})
		return
	}
	if required {
		c.JSON(http.StatusConflict, gin.H{"error": "setup required", "setup_required": true})
		return
	}

	var req AuthCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}
	username := strings.TrimSpace(req.Username)
	ok, authErr := authenticateUser(username, req.Password)
	if authErr != nil && !errors.Is(authErr, errSetupRequired) {
		log.Printf("handleAuthLogin: authentication failed for username=%q: %v", username, authErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		return
	}
	if !ok {
		auditWithActor("unknown", clientIPFromContext(c), "auth.login", "auth_user", username, "failure", "Invalid credentials", nil)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	sm := currentSessionManager()
	if sm == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session manager not initialized"})
		return
	}
	if err := sm.RenewToken(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to renew session"})
		return
	}
	sm.Put(c.Request.Context(), authSessionUserKey, username)
	c.Set("actor", username)
	audit(c, "auth.login", "auth_user", username, "success", "User logged in", nil)
	c.JSON(http.StatusOK, gin.H{"message": "login successful"})
}

func handleAuthLogout(c *gin.Context) {
	if !sameOriginAuthRequest(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "cross-site logout request denied"})
		return
	}
	actor := sessionUsername(c)
	sm := currentSessionManager()
	if sm == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session manager not initialized"})
		return
	}
	if err := sm.Destroy(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
		return
	}
	auditWithActor(actor, clientIPFromContext(c), "auth.logout", "auth_user", actor, "success", "User logged out", nil)
	c.JSON(http.StatusOK, gin.H{"message": "logout successful"})
}
