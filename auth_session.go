package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	authpkg "debian-updater/internal/auth"

	"github.com/alexedwards/argon2id"
	"github.com/alexedwards/scs/v2"
	"github.com/gin-gonic/gin"
)

const (
	sessionCookieSecureEnv        = authpkg.SessionCookieSecureEnv
	sessionIdleTimeoutHoursEnv    = authpkg.SessionIdleTimeoutHoursEnv
	authSessionUserKey            = authpkg.SessionUserKey
	authUserID                    = authpkg.UserID
	authMinPasswordLen            = authpkg.MinPasswordLen
	authMaxPasswordLen            = authpkg.MaxPasswordLen
	authMaxRequestBytes           = authpkg.MaxRequestBytes
	authLoginRateLimitMaxAttempts = authpkg.LoginRateLimitMaxAttempts
	authPasswordChangeMaxAttempts = authpkg.PasswordChangeMaxAttempts
	authSetupRateLimitMaxAttempts = authpkg.SetupRateLimitMaxAttempts
	metricsRateLimitMaxAttempts   = authpkg.MetricsRateLimitMaxAttempts
	authRateLimitWindow           = authpkg.RateLimitWindow
	metricsRateLimitWindow        = authpkg.MetricsRateLimitWindow
	defaultSessionLifetime        = authpkg.DefaultSessionLifetime
)

var sessionManager *scs.SessionManager
var sessionManagerMu sync.RWMutex

var (
	errSetupAlreadyCompleted = authpkg.ErrSetupAlreadyCompleted
	errSetupRequired         = authpkg.ErrSetupRequired
	errAuthPasswordMismatch  = authpkg.ErrPasswordMismatch
)

type AuthService = authpkg.Service
type AuthRateLimiter = authpkg.RateLimiter
type AuthRateBucket = authpkg.RateBucket
type AuthCredentialsRequest = authpkg.CredentialsRequest
type AuthPasswordChangeRequest = authpkg.PasswordChangeRequest

var authService = NewAuthService(getDB)

func NewAuthService(db authpkg.DBProvider) *AuthService {
	return authpkg.NewService(authpkg.ServiceOptions{DB: db})
}

func NewAuthRateLimiter(window time.Duration, max int) *AuthRateLimiter {
	return authpkg.NewRateLimiter(window, max)
}

func limitAuthRequestBody(c *gin.Context) {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, authMaxRequestBytes)
}

func authRequestBodyTooLarge(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

var (
	loginRateLimiter          = NewAuthRateLimiter(authRateLimitWindow, authLoginRateLimitMaxAttempts)
	passwordChangeRateLimiter = NewAuthRateLimiter(authRateLimitWindow, authPasswordChangeMaxAttempts)
	setupRateLimiter          = NewAuthRateLimiter(authRateLimitWindow, authSetupRateLimitMaxAttempts)
	metricsRateLimiter        = NewAuthRateLimiter(metricsRateLimitWindow, metricsRateLimitMaxAttempts)
)

const authRuntimeDepsContextKey = "auth_runtime_deps"

type authRuntimeDeps struct {
	service                   *AuthService
	loginRateLimiter          *AuthRateLimiter
	passwordChangeRateLimiter *AuthRateLimiter
	setupRateLimiter          *AuthRateLimiter
}

func authRuntimeMiddleware(deps AppDeps) gin.HandlerFunc {
	deps = deps.withDefaults()
	runtime := authRuntimeDeps{
		service:                   deps.AuthService,
		loginRateLimiter:          deps.LoginRateLimiter,
		passwordChangeRateLimiter: deps.PasswordChangeRateLimiter,
		setupRateLimiter:          deps.SetupRateLimiter,
	}
	return func(c *gin.Context) {
		c.Set(authRuntimeDepsContextKey, runtime)
		c.Next()
	}
}

func authRuntimeFromContext(c *gin.Context) (authRuntimeDeps, bool) {
	if c == nil {
		return authRuntimeDeps{}, false
	}
	value, ok := c.Get(authRuntimeDepsContextKey)
	if !ok {
		return authRuntimeDeps{}, false
	}
	runtime, ok := value.(authRuntimeDeps)
	return runtime, ok
}

func authServiceForContext(c *gin.Context) *AuthService {
	if runtime, ok := authRuntimeFromContext(c); ok && runtime.service != nil {
		return runtime.service
	}
	return authService
}

func sessionManagerForContext(c *gin.Context) *scs.SessionManager {
	return currentSessionManager()
}

func loginRateLimiterForContext(c *gin.Context) *AuthRateLimiter {
	if runtime, ok := authRuntimeFromContext(c); ok && runtime.loginRateLimiter != nil {
		return runtime.loginRateLimiter
	}
	return loginRateLimiter
}

func passwordChangeRateLimiterForContext(c *gin.Context) *AuthRateLimiter {
	if runtime, ok := authRuntimeFromContext(c); ok && runtime.passwordChangeRateLimiter != nil {
		return runtime.passwordChangeRateLimiter
	}
	return passwordChangeRateLimiter
}

func setupRateLimiterForContext(c *gin.Context) *AuthRateLimiter {
	if runtime, ok := authRuntimeFromContext(c); ok && runtime.setupRateLimiter != nil {
		return runtime.setupRateLimiter
	}
	return setupRateLimiter
}

func StopAuthRateLimiters() {
	if loginRateLimiter != nil {
		loginRateLimiter.Stop()
	}
	if passwordChangeRateLimiter != nil {
		passwordChangeRateLimiter.Stop()
	}
	if setupRateLimiter != nil {
		setupRateLimiter.Stop()
	}
	if metricsRateLimiter != nil {
		metricsRateLimiter.Stop()
	}
}

func bindAuthCredentialsRequest(c *gin.Context, requirePasswordConfirm bool) (AuthCredentialsRequest, bool, error) {
	if c == nil || c.Request == nil {
		return AuthCredentialsRequest{}, false, errors.New("missing request")
	}
	contentType := strings.ToLower(strings.TrimSpace(c.ContentType()))
	switch contentType {
	case "application/x-www-form-urlencoded", "multipart/form-data":
		if err := c.Request.ParseForm(); err != nil {
			return AuthCredentialsRequest{}, true, err
		}
		req := AuthCredentialsRequest{
			Username: c.PostForm("username"),
			Password: c.PostForm("password"),
		}
		if requirePasswordConfirm && req.Password != c.PostForm("password-confirm") {
			return req, true, errAuthPasswordMismatch
		}
		return req, true, nil
	default:
		var req AuthCredentialsRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			return AuthCredentialsRequest{}, false, err
		}
		return req, false, nil
	}
}

func writeAuthFormError(c *gin.Context, status int, message string) {
	setNoStoreHeaders(c)
	c.String(status, message)
}

func newSessionManager(db *sql.DB) (*scs.SessionManager, error) {
	return authpkg.NewSessionManager(db, authpkg.SessionManagerOptions{
		SecureCookieEnv:     sessionCookieSecureEnv,
		IdleTimeoutHoursEnv: sessionIdleTimeoutHoursEnv,
		CookieName:          authpkg.DefaultSessionCookieName,
		Lifetime:            defaultSessionLifetime,
		Logf:                log.Printf,
	})
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
	return authService.SetupRequired()
}

func setupRequiredForContext(c *gin.Context) (bool, error) {
	return authServiceForContext(c).SetupRequired()
}

func getSingleUser() (username, passwordHash string, exists bool, err error) {
	return authService.GetSingleUser()
}

func validatePasswordPolicy(password string) error {
	return authService.ValidatePasswordPolicy(password)
}

func validateAuthUsername(username string) error {
	return authService.ValidateUsername(username)
}

func createInitialUser(username, password string) error {
	return authService.CreateInitialUser(username, password)
}

func createInitialUserForContext(c *gin.Context, username, password string) error {
	return authServiceForContext(c).CreateInitialUser(username, password)
}

func authenticateUser(username, password string) (bool, error) {
	return authService.Authenticate(username, password)
}

func authenticateUserForContext(c *gin.Context, username, password string) (bool, error) {
	return authServiceForContext(c).Authenticate(username, password)
}

//lint:ignore U1000 compatibility wrapper retained for transitional call sites.
func changeSingleUserPassword(currentPassword, newPassword, confirmPassword string) error {
	return authService.ChangePassword(currentPassword, newPassword, confirmPassword)
}

func changeSingleUserPasswordForContext(c *gin.Context, currentPassword, newPassword, confirmPassword string) error {
	return authServiceForContext(c).ChangePassword(currentPassword, newPassword, confirmPassword)
}

func countStoredSessions() (int, error) {
	return authService.CountSessions()
}

func countStoredSessionsForContext(c *gin.Context) (int, error) {
	return authServiceForContext(c).CountSessions()
}

//lint:ignore U1000 compatibility wrapper retained for transitional call sites.
func clearStoredSessions() (int64, error) {
	return authService.ClearSessions()
}

func clearStoredSessionsForContext(c *gin.Context) (int64, error) {
	return authServiceForContext(c).ClearSessions()
}

func sessionUsername(c *gin.Context) string {
	return authpkg.SessionUsername(c, sessionManagerForContext(c))
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
	return authpkg.SameOriginRequest(c)
}

func sameOriginWriteMiddleware() gin.HandlerFunc {
	return authpkg.SameOriginWriteMiddleware()
}

func backupRestoreBarrierMiddleware(barriers ...*BackupBarrier) gin.HandlerFunc {
	barrier := backupRestoreBarrier
	if len(barriers) > 0 && barriers[0] != nil {
		barrier = barriers[0]
	}
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
		if backupRestoreBarrierBypassPath(path) {
			c.Next()
			return
		}
		if maintenanceExclusivePath(path) {
			if !barrier.TryLock() {
				writeMaintenanceBlockedResponse(c)
				return
			}
			defer barrier.Unlock()
			if currentMaintenanceState().Active {
				writeMaintenanceBlockedResponse(c)
				return
			}
			c.Next()
			return
		}
		if !barrier.TryRLock() {
			writeMaintenanceBlockedResponse(c)
			return
		}
		defer barrier.RUnlock()
		if currentMaintenanceState().Active {
			writeMaintenanceBlockedResponse(c)
			return
		}
		c.Next()
	}
}

func backupRestoreBarrierBypassPath(path string) bool {
	return path == "/api/dashboard/events"
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
		if metricsRateLimiter != nil && !metricsRateLimiter.Allow(rateLimitClientIP(c)) {
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
		required, err := setupRequiredForContext(c)
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
	required, err := setupRequiredForContext(c)
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
	required, err := setupRequiredForContext(c)
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
	required, err := setupRequiredForContext(c)
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

func handleAuthSessionsStatus(c *gin.Context) {
	count, err := countStoredSessionsForContext(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count sessions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"session_count": count})
}

func handleAuthPasswordChange(c *gin.Context) {
	key := fmt.Sprintf("%s:%s:password-change", rateLimitClientIP(c), sessionUsername(c))
	recordPasswordChangeFailure := func() {
		if limiter := passwordChangeRateLimiterForContext(c); limiter != nil {
			limiter.RecordFailure(key)
		}
	}
	if limiter := passwordChangeRateLimiterForContext(c); limiter != nil && limiter.Limited(key) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many password change attempts"})
		return
	}
	var req AuthPasswordChangeRequest
	limitAuthRequestBody(c)
	if err := c.ShouldBindJSON(&req); err != nil {
		recordPasswordChangeFailure()
		if authRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request payload too large"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}
	if strings.TrimSpace(req.CurrentPassword) == "" || strings.TrimSpace(req.NewPassword) == "" {
		recordPasswordChangeFailure()
		c.JSON(http.StatusBadRequest, gin.H{"error": "current_password and new_password are required"})
		return
	}
	if err := changeSingleUserPasswordForContext(c, req.CurrentPassword, req.NewPassword, req.ConfirmPassword); err != nil {
		recordPasswordChangeFailure()
		status := http.StatusBadRequest
		message := err.Error()
		if errors.Is(err, errSetupRequired) {
			status = http.StatusConflict
			message = "setup required"
		}
		audit(c, "auth.password.change", "auth_user", sessionUsername(c), "failure", "Password change failed", map[string]any{"error": message})
		c.JSON(status, gin.H{"error": message})
		return
	}
	audit(c, "auth.password.change", "auth_user", sessionUsername(c), "success", "Password changed", nil)
	c.JSON(http.StatusOK, gin.H{"message": "password changed"})
}

func handleAuthSessionsClear(c *gin.Context) {
	actor := sessionUsername(c)
	deleted, err := clearStoredSessionsForContext(c)
	if err != nil {
		audit(c, "auth.sessions.clear", "auth_user", actor, "failure", "Failed to clear sessions", map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to clear sessions"})
		return
	}
	auditWithActor(actor, clientIPFromContext(c), "auth.sessions.clear", "auth_user", actor, "success", "All sessions cleared", map[string]any{"deleted_sessions": deleted})
	c.JSON(http.StatusOK, gin.H{"message": "sessions cleared", "deleted_sessions": deleted})
}

func handleAuthSetup(c *gin.Context) {
	if !sameOriginAuthRequest(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "cross-site setup request denied"})
		return
	}
	key := fmt.Sprintf("%s:setup", rateLimitClientIP(c))
	if limiter := setupRateLimiterForContext(c); limiter != nil && !limiter.Allow(key) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many setup attempts"})
		return
	}
	required, err := setupRequiredForContext(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to evaluate setup state"})
		return
	}
	if !required {
		c.JSON(http.StatusConflict, gin.H{"error": "setup already completed"})
		return
	}

	limitAuthRequestBody(c)
	req, formPost, err := bindAuthCredentialsRequest(c, true)
	if err != nil {
		if authRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request payload too large"})
			return
		}
		if errors.Is(err, errAuthPasswordMismatch) {
			if formPost {
				writeAuthFormError(c, http.StatusBadRequest, err.Error())
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
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
	if err := createInitialUserForContext(c, username, password); err != nil {
		switch {
		case errors.Is(err, errSetupAlreadyCompleted):
			c.JSON(http.StatusConflict, gin.H{"error": "setup already completed"})
		default:
			log.Printf("handleAuthSetup: failed to create initial user for username=%q: %v", username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		}
		return
	}

	sm := sessionManagerForContext(c)
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
	if formPost {
		c.Redirect(http.StatusSeeOther, "/")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "setup complete"})
}

func handleAuthLogin(c *gin.Context) {
	if !sameOriginAuthRequest(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "cross-site login request denied"})
		return
	}
	key := fmt.Sprintf("%s:login", rateLimitClientIP(c))
	if limiter := loginRateLimiterForContext(c); limiter != nil && !limiter.Allow(key) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many login attempts"})
		return
	}
	required, err := setupRequiredForContext(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to evaluate setup state"})
		return
	}
	if required {
		c.JSON(http.StatusConflict, gin.H{"error": "setup required", "setup_required": true})
		return
	}

	limitAuthRequestBody(c)
	req, formPost, err := bindAuthCredentialsRequest(c, false)
	if err != nil {
		if authRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request payload too large"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}
	username := strings.TrimSpace(req.Username)
	ok, authErr := authenticateUserForContext(c, username, req.Password)
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

	sm := sessionManagerForContext(c)
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
	if formPost {
		c.Redirect(http.StatusSeeOther, "/")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "login successful"})
}

func handleAuthLogout(c *gin.Context) {
	if !sameOriginAuthRequest(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "cross-site logout request denied"})
		return
	}
	actor := sessionUsername(c)
	sm := sessionManagerForContext(c)
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
