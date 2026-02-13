package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	_ "modernc.org/sqlite"
)

type Server struct {
	Name string   `json:"name"`
	Host string   `json:"host"`
	Port int      `json:"port"`
	User string   `json:"user"`
	Pass string   `json:"pass"`
	Key  string   `json:"-"`
	Tags []string `json:"tags"`
}

type ServerStatus struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	User        string   `json:"user"`
	Status      string   `json:"status"` // idle, updating, pending_approval, approved, cancelled, upgrading, autoremove, sudoers, done, error
	Logs        string   `json:"logs"`
	Upgradable  []string `json:"upgradable"`
	HasPassword bool     `json:"has_password"`
	HasKey      bool     `json:"has_key"`
	Tags        []string `json:"tags"`
}

var servers []Server
var statusMap = make(map[string]*ServerStatus)
var mu sync.Mutex

var db *sql.DB
var dbOnce sync.Once
var keyOnce sync.Once
var encryptionKey []byte
var globalKeyMu sync.RWMutex
var globalKey string
var knownHostsMu sync.Mutex
var scanHostKeyFunc = scanHostKey
var saveServersFunc = saveServers
var auditPruneTickerOnce sync.Once

const configFileName = "config.json"
const legacyServersFileName = "servers.json"
const globalKeySetting = "global_ssh_key"
const basicAuthUserEnv = "DEBIAN_UPDATER_BASIC_AUTH_USER"
const basicAuthPassEnv = "DEBIAN_UPDATER_BASIC_AUTH_PASS"
const maxUploadedKeyBytes = 64 * 1024
const sshConnectTimeout = 15 * time.Second
const auditRetentionDays = 90
const auditPruneInterval = 12 * time.Hour
const auditMessageMaxLen = 512
const auditMetaMaxLen = 2048
const retryMaxAttemptsEnv = "DEBIAN_UPDATER_RETRY_MAX_ATTEMPTS"
const retryBaseDelayMSEnv = "DEBIAN_UPDATER_RETRY_BASE_DELAY_MS"
const retryMaxDelayMSEnv = "DEBIAN_UPDATER_RETRY_MAX_DELAY_MS"
const retryJitterPctEnv = "DEBIAN_UPDATER_RETRY_JITTER_PCT"
const updatePrecheckMinFreeKB int64 = 1024 * 1024
const precheckOutputMaxLen = 240
const precheckDiskSpaceCmd = "df -Pk /var / | awk 'NR>1 {print $4}'"
const precheckLocksCmd = "sudo /usr/bin/fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock"
const precheckDpkgAuditCmd = "sudo dpkg --audit"
const precheckAptCheckCmd = "sudo apt-get check"

var errUploadedKeyTooLarge = errors.New("key file too large (max 64KB)")
var errUploadedKeyEmpty = errors.New("empty key")
var errActionInProgress = errors.New("action already in progress")
var errFingerprintMismatch = errors.New("host key fingerprint mismatch")

type AuditEvent struct {
	ID         int64  `json:"id"`
	CreatedAt  string `json:"created_at"`
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetName string `json:"target_name"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	MetaJSON   string `json:"meta_json"`
	RequestID  string `json:"request_id"`
	ClientIP   string `json:"client_ip"`
}

type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	JitterPct   int
}

type updatePrecheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
	Output  string `json:"output,omitempty"`
}

type updatePrecheckSummary struct {
	AllPassed   bool                   `json:"all_passed"`
	FailedCheck string                 `json:"failed_check,omitempty"`
	Results     []updatePrecheckResult `json:"results"`
}

type retryableTaggedError struct {
	err error
}

type sshSessionRunner interface {
	SetStdin(io.Reader)
	SetStdout(io.Writer)
	SetStderr(io.Writer)
	Run(string) error
	Close() error
}

type sshConnection interface {
	NewSession() (sshSessionRunner, error)
	Close() error
}

type realSSHSession struct {
	session *ssh.Session
}

func (s *realSSHSession) SetStdin(r io.Reader)  { s.session.Stdin = r }
func (s *realSSHSession) SetStdout(w io.Writer) { s.session.Stdout = w }
func (s *realSSHSession) SetStderr(w io.Writer) { s.session.Stderr = w }
func (s *realSSHSession) Run(cmd string) error  { return s.session.Run(cmd) }
func (s *realSSHSession) Close() error          { return s.session.Close() }

type realSSHConnection struct {
	client *ssh.Client
}

func (c *realSSHConnection) NewSession() (sshSessionRunner, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	return &realSSHSession{session: session}, nil
}

func (c *realSSHConnection) Close() error {
	return c.client.Close()
}

var dialSSHConnection = func(server Server, config *ssh.ClientConfig) (sshConnection, error) {
	client, err := ssh.Dial("tcp", net.JoinHostPort(server.Host, strconv.Itoa(normalizePort(server.Port))), config)
	if err != nil {
		return nil, err
	}
	return &realSSHConnection{client: client}, nil
}

func (e retryableTaggedError) Error() string {
	return e.err.Error()
}

func (e retryableTaggedError) Unwrap() error {
	return e.err
}

func (e retryableTaggedError) Retryable() bool {
	return true
}

func dbPath() string {
	if p := strings.TrimSpace(os.Getenv("DEBIAN_UPDATER_DB_PATH")); p != "" {
		return p
	}
	if dirExists("/data") {
		return filepath.Join("/data", "servers.db")
	}
	return filepath.Join("data", "servers.db")
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func configPath() string {
	return filepath.Join(filepath.Dir(dbPath()), configFileName)
}

func getDB() *sql.DB {
	dbOnce.Do(func() {
		path := dbPath()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			log.Fatalf("Failed to create db directory: %v", err)
		}
		var err error
		db, err = sql.Open("sqlite", path)
		if err != nil {
			log.Fatalf("Failed to open sqlite db: %v", err)
		}
		_, err = db.Exec(`
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
		`)
		if err != nil {
			log.Fatalf("Failed to initialize db schema: %v", err)
		}
		if err := ensureSchema(db); err != nil {
			log.Fatalf("Failed to migrate db schema: %v", err)
		}
	})
	return db
}

func getEncryptionKey() []byte {
	keyOnce.Do(func() {
		path := configPath()
		var cfg map[string]string
		if data, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(data, &cfg); err != nil {
				log.Fatalf("Failed to parse %s: %v", path, err)
			}
		} else if !os.IsNotExist(err) {
			log.Fatalf("Failed to read %s: %v", path, err)
		}

		keyStr := ""
		if cfg != nil {
			keyStr = strings.TrimSpace(cfg["encryption_key"])
		}

		if keyStr == "" {
			keyBytes := make([]byte, 32)
			if _, err := rand.Read(keyBytes); err != nil {
				log.Fatalf("Failed to generate encryption key: %v", err)
			}
			keyStr = base64.StdEncoding.EncodeToString(keyBytes)
			cfg = map[string]string{"encryption_key": keyStr}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				log.Fatalf("Failed to create config dir: %v", err)
			}
			data, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				log.Fatalf("Failed to serialize config: %v", err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				log.Fatalf("Failed to write %s: %v", path, err)
			}
		}

		keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil || len(keyBytes) != 32 {
			log.Fatalf("Invalid encryption_key in %s (must be base64 32 bytes)", path)
		}
		encryptionKey = keyBytes
	})
	return encryptionKey
}

func ensureSchema(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(servers)")
	if err != nil {
		return err
	}
	defer rows.Close()
	hasKeyPath := false
	hasKeyEnc := false
	hasTags := false
	hasPort := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "key_path" {
			hasKeyPath = true
		}
		if name == "key_enc" {
			hasKeyEnc = true
		}
		if name == "tags" {
			hasTags = true
		}
		if name == "port" {
			hasPort = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasKeyPath {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN key_path TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !hasKeyEnc {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN key_enc TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !hasTags {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN tags TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !hasPort {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN port INTEGER NOT NULL DEFAULT 22"); err != nil {
			return err
		}
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"); err != nil {
		return err
	}
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
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events (created_at DESC)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_events (target_type, target_name, created_at DESC)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events (action, created_at DESC)"); err != nil {
		return err
	}
	return nil
}

func truncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(strings.TrimSpace(s))
	if len(runes) <= maxLen {
		return string(runes)
	}
	return string(runes[:maxLen])
}

func normalizeAuditFilterTimestamp(raw string) (string, error) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	return parsed.UTC().Format(time.RFC3339), nil
}

func updateCompletionOutcome(finalStatus string) string {
	switch finalStatus {
	case "done":
		return "success"
	case "idle":
		return "ignored"
	default:
		return "failure"
	}
}

func parseIntEnvWithDefault(envKey string, defaultValue int) int {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("Invalid %s=%q, using default %d", envKey, raw, defaultValue)
		return defaultValue
	}
	return parsed
}

func loadRetryPolicyFromEnv() RetryPolicy {
	p := RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   1 * time.Second,
		MaxDelay:    8 * time.Second,
		JitterPct:   20,
	}
	attempts := parseIntEnvWithDefault(retryMaxAttemptsEnv, p.MaxAttempts)
	if attempts < 1 || attempts > 10 {
		log.Printf("Invalid %s=%d, must be in [1,10], using default %d", retryMaxAttemptsEnv, attempts, p.MaxAttempts)
	} else {
		p.MaxAttempts = attempts
	}
	baseDelayMs := parseIntEnvWithDefault(retryBaseDelayMSEnv, int(p.BaseDelay/time.Millisecond))
	if baseDelayMs <= 0 {
		log.Printf("Invalid %s=%d, must be > 0, using default %d", retryBaseDelayMSEnv, baseDelayMs, int(p.BaseDelay/time.Millisecond))
	} else {
		p.BaseDelay = time.Duration(baseDelayMs) * time.Millisecond
	}
	maxDelayMs := parseIntEnvWithDefault(retryMaxDelayMSEnv, int(p.MaxDelay/time.Millisecond))
	if maxDelayMs <= 0 {
		log.Printf("Invalid %s=%d, must be > 0, using default %d", retryMaxDelayMSEnv, maxDelayMs, int(p.MaxDelay/time.Millisecond))
	} else {
		p.MaxDelay = time.Duration(maxDelayMs) * time.Millisecond
	}
	if p.MaxDelay < p.BaseDelay {
		log.Printf("Invalid retry delay configuration: max delay %v lower than base delay %v, using defaults", p.MaxDelay, p.BaseDelay)
		p.BaseDelay = 1 * time.Second
		p.MaxDelay = 8 * time.Second
	}
	jitterPct := parseIntEnvWithDefault(retryJitterPctEnv, p.JitterPct)
	if jitterPct < 0 || jitterPct > 50 {
		log.Printf("Invalid %s=%d, must be in [0,50], using default %d", retryJitterPctEnv, jitterPct, p.JitterPct)
	} else {
		p.JitterPct = jitterPct
	}
	return p
}

func isRetryableMessage(msg string) bool {
	normalized := strings.ToLower(strings.TrimSpace(msg))
	if normalized == "" {
		return false
	}

	nonRetryableHints := []string{
		"unable to authenticate",
		"permission denied",
		"no auth",
		"authentication",
		"host key",
		"knownhosts",
		"missing password or ssh key",
		"fingerprint mismatch",
		"invalid credentials",
		"invalid key",
		"invalid private key",
	}
	for _, hint := range nonRetryableHints {
		if strings.Contains(normalized, hint) {
			return false
		}
	}

	retryableHints := []string{
		"i/o timeout",
		"timeout",
		"connection reset",
		"connection refused",
		"broken pipe",
		"eof",
		"temporarily unavailable",
		"resource temporarily unavailable",
		"could not get lock",
		"dpkg frontend lock",
		"network is unreachable",
		"no route to host",
		"connection closed",
	}
	for _, hint := range retryableHints {
		if strings.Contains(normalized, hint) {
			return true
		}
	}
	return false
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	var tagged interface{ Retryable() bool }
	if errors.As(err, &tagged) && tagged.Retryable() {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}
	return isRetryableMessage(err.Error())
}

func markRetryableFromOutput(err error, output string) error {
	if err == nil {
		return nil
	}
	if isRetryableMessage(output) {
		return retryableTaggedError{err: err}
	}
	return err
}

func computeRetryDelay(policy RetryPolicy, failedAttempt int, jitterRand float64) time.Duration {
	if failedAttempt < 1 {
		failedAttempt = 1
	}
	delay := float64(policy.BaseDelay) * math.Pow(2, float64(failedAttempt-1))
	maxDelay := float64(policy.MaxDelay)
	if delay > maxDelay {
		delay = maxDelay
	}
	if policy.JitterPct > 0 {
		// jitterRand in [0,1) maps to [-1,1)
		jitterFactor := (jitterRand*2 - 1) * (float64(policy.JitterPct) / 100.0)
		delay = delay * (1 + jitterFactor)
	}
	if delay > maxDelay {
		delay = maxDelay
	}
	if delay < float64(time.Millisecond) {
		delay = float64(time.Millisecond)
	}
	return time.Duration(delay)
}

func runWithRetryWithSleep(
	policy RetryPolicy,
	opName string,
	fn func() error,
	onRetry func(attempt int, wait time.Duration, err error),
	sleepFn func(time.Duration),
) error {
	if policy.MaxAttempts < 1 {
		policy.MaxAttempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if !isRetryableError(lastErr) {
			return lastErr
		}
		if attempt == policy.MaxAttempts {
			break
		}
		wait := computeRetryDelay(policy, attempt, mathrand.Float64())
		if onRetry != nil {
			onRetry(attempt, wait, lastErr)
		}
		if sleepFn != nil {
			sleepFn(wait)
		}
	}
	if lastErr != nil && isRetryableError(lastErr) {
		log.Printf("Retry exhausted for %s after %d attempts: %v", opName, policy.MaxAttempts, lastErr)
	}
	return lastErr
}

func runWithRetry(policy RetryPolicy, opName string, fn func() error, onRetry func(attempt int, wait time.Duration, err error)) error {
	return runWithRetryWithSleep(policy, opName, fn, onRetry, time.Sleep)
}

func reconnectSSHClient(server Server, config *ssh.ClientConfig, clientRef *sshConnection) error {
	if clientRef != nil && *clientRef != nil {
		(*clientRef).Close()
		*clientRef = nil
	}
	conn, err := dialSSHConnection(server, config)
	if err != nil {
		return err
	}
	if clientRef != nil {
		*clientRef = conn
	} else {
		conn.Close()
	}
	return nil
}

func appendStatusRetryLog(serverName string, format string, args ...any) {
	mu.Lock()
	if status := statusMap[serverName]; status != nil {
		status.Logs += fmt.Sprintf(format, args...)
	}
	mu.Unlock()
}

func dialSSHWithRetry(server Server, config *ssh.ClientConfig, policy RetryPolicy, opName string, attemptsUsed *int) (sshConnection, error) {
	var client sshConnection
	err := runWithRetry(policy, opName, func() error {
		if attemptsUsed != nil {
			*attemptsUsed += 1
		}
		c, dialErr := dialSSHConnection(server, config)
		if dialErr == nil {
			if client != nil {
				_ = client.Close()
			}
			client = c
		}
		return dialErr
	}, func(attempt int, wait time.Duration, retryErr error) {
		appendStatusRetryLog(
			server.Name,
			"\nSSH dial attempt %d/%d failed: %v; retrying in %s",
			attempt,
			policy.MaxAttempts,
			retryErr,
			wait.Round(time.Millisecond),
		)
	})
	return client, err
}

func runSSHOperationWithRetry(
	server Server,
	config *ssh.ClientConfig,
	clientRef *sshConnection,
	policy RetryPolicy,
	opName string,
	retryLogFormat string,
	attemptsUsed *int,
	operation func() error,
) error {
	attempt := 0
	return runWithRetry(policy, opName, func() error {
		if attemptsUsed != nil {
			*attemptsUsed += 1
		}
		attempt++
		if attempt > 1 {
			if reconnectErr := reconnectSSHClient(server, config, clientRef); reconnectErr != nil {
				return reconnectErr
			}
		}
		return operation()
	}, func(retryAttempt int, wait time.Duration, retryErr error) {
		appendStatusRetryLog(
			server.Name,
			retryLogFormat,
			retryAttempt,
			policy.MaxAttempts,
			retryErr,
			wait.Round(time.Millisecond),
		)
	})
}

func compactCommandOutput(stdout, stderr string) string {
	combined := strings.TrimSpace(strings.TrimSpace(stdout) + "\n" + strings.TrimSpace(stderr))
	if combined == "" {
		return ""
	}
	return truncateString(combined, precheckOutputMaxLen)
}

func kbToGiB(kb int64) float64 {
	return float64(kb) / (1024.0 * 1024.0)
}

func isSudoPolicyOrPasswordError(msg string) bool {
	normalized := strings.ToLower(strings.TrimSpace(msg))
	return strings.Contains(normalized, "a password is required") ||
		strings.Contains(normalized, "not allowed to run sudo") ||
		strings.Contains(normalized, "is not in the sudoers file")
}

func isCommandNotFoundError(msg string) bool {
	normalized := strings.ToLower(strings.TrimSpace(msg))
	return strings.Contains(normalized, "/usr/bin/fuser: command not found") ||
		strings.Contains(normalized, "/usr/bin/fuser: not found") ||
		strings.Contains(normalized, "unable to execute /usr/bin/fuser") ||
		strings.Contains(normalized, "sudo: /usr/bin/fuser: no such file or directory") ||
		(strings.Contains(normalized, "command not found") && strings.Contains(normalized, "fuser"))
}

func isBenignNoLockStateOutput(msg string) bool {
	normalized := strings.ToLower(strings.TrimSpace(msg))
	if normalized == "" {
		return true
	}
	if strings.Contains(normalized, "no process found") {
		return true
	}
	lockPathMentioned := strings.Contains(normalized, "/var/lib/dpkg/lock-frontend") ||
		strings.Contains(normalized, "/var/lib/dpkg/lock") ||
		strings.Contains(normalized, "/var/cache/apt/archives/lock")
	if lockPathMentioned && (strings.Contains(normalized, "does not exist") || strings.Contains(normalized, "no such file or directory")) {
		return true
	}
	return false
}

func runSSHCommand(client sshConnection, cmd string, stdin io.Reader) (string, string, error) {
	if client == nil {
		return "", "", errors.New("missing SSH connection")
	}
	session, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.SetStdout(&stdout)
	session.SetStderr(&stderr)
	if stdin != nil {
		session.SetStdin(stdin)
	}
	err = session.Run(cmd)
	return stdout.String(), stderr.String(), err
}

func sshExitCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	var exitStatusErr interface{ ExitStatus() int }
	if errors.As(err, &exitStatusErr) {
		return exitStatusErr.ExitStatus(), true
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), true
	}
	return 0, false
}

func checkDiskSpace(client sshConnection) updatePrecheckResult {
	stdout, stderr, err := runSSHCommand(client, precheckDiskSpaceCmd, nil)
	output := compactCommandOutput(stdout, stderr)
	if err != nil {
		return updatePrecheckResult{
			Name:    "disk_space",
			Passed:  false,
			Details: fmt.Sprintf("Failed to read free disk space: %v", err),
			Output:  output,
		}
	}
	fields := strings.Fields(stdout)
	if len(fields) == 0 {
		return updatePrecheckResult{
			Name:    "disk_space",
			Passed:  false,
			Details: "Could not parse free disk space output.",
			Output:  output,
		}
	}
	minFreeKB := int64(-1)
	for _, field := range fields {
		value, convErr := strconv.ParseInt(strings.TrimSpace(field), 10, 64)
		if convErr != nil {
			return updatePrecheckResult{
				Name:    "disk_space",
				Passed:  false,
				Details: fmt.Sprintf("Invalid free space value %q.", field),
				Output:  output,
			}
		}
		if minFreeKB == -1 || value < minFreeKB {
			minFreeKB = value
		}
	}
	if minFreeKB < updatePrecheckMinFreeKB {
		return updatePrecheckResult{
			Name:    "disk_space",
			Passed:  false,
			Details: fmt.Sprintf("Insufficient disk space: %.2f GiB free (minimum %.2f GiB).", kbToGiB(minFreeKB), kbToGiB(updatePrecheckMinFreeKB)),
			Output:  "",
		}
	}
	return updatePrecheckResult{
		Name:    "disk_space",
		Passed:  true,
		Details: fmt.Sprintf("Disk space OK: %.2f GiB free (minimum %.2f GiB).", kbToGiB(minFreeKB), kbToGiB(updatePrecheckMinFreeKB)),
		Output:  "",
	}
}

func checkAptLocks(client sshConnection) updatePrecheckResult {
	stdout, stderr, err := runSSHCommand(client, precheckLocksCmd, nil)
	output := compactCommandOutput(stdout, stderr)
	if err == nil {
		return updatePrecheckResult{
			Name:    "apt_locks",
			Passed:  false,
			Details: "APT/DPKG lock files are currently in use.",
			Output:  output,
		}
	}
	if isSudoPolicyOrPasswordError(output + "\n" + err.Error()) {
		return updatePrecheckResult{
			Name:    "apt_locks",
			Passed:  false,
			Details: "Lock pre-check requires passwordless sudo for `/usr/bin/fuser`. Click \"Enable passwordless apt\" for this server, then retry.",
			Output:  output,
		}
	}
	if isCommandNotFoundError(output + "\n" + err.Error()) {
		return updatePrecheckResult{
			Name:    "apt_locks",
			Passed:  false,
			Details: "Lock check command not found on remote host. Install package `psmisc` (provides /usr/bin/fuser).",
			Output:  output,
		}
	}
	if exitCode, ok := sshExitCode(err); ok && exitCode == 1 {
		trimmedOutput := strings.TrimSpace(output)
		if !isBenignNoLockStateOutput(trimmedOutput) {
			return updatePrecheckResult{
				Name:    "apt_locks",
				Passed:  false,
				Details: "Could not determine apt/dpkg lock state from lock check output.",
				Output:  output,
			}
		}
		return updatePrecheckResult{
			Name:    "apt_locks",
			Passed:  true,
			Details: "No apt/dpkg lock contention detected.",
			Output:  output,
		}
	}
	if exitCode, ok := sshExitCode(err); ok && exitCode == 127 {
		return updatePrecheckResult{
			Name:    "apt_locks",
			Passed:  false,
			Details: "Lock check command not found on remote host. Install package `psmisc` (provides /usr/bin/fuser).",
			Output:  output,
		}
	}
	return updatePrecheckResult{
		Name:    "apt_locks",
		Passed:  false,
		Details: fmt.Sprintf("Failed to evaluate apt/dpkg lock state: %v", err),
		Output:  output,
	}
}

func checkAptHealth(client sshConnection) updatePrecheckResult {
	dpkgStdout, dpkgStderr, dpkgErr := runSSHCommand(client, precheckDpkgAuditCmd, nil)
	dpkgOutput := compactCommandOutput(dpkgStdout, dpkgStderr)
	if dpkgErr != nil {
		if isSudoPolicyOrPasswordError(dpkgOutput + "\n" + dpkgErr.Error()) {
			return updatePrecheckResult{
				Name:    "apt_health",
				Passed:  false,
				Details: "APT health pre-check requires passwordless sudo for `/usr/bin/dpkg`. Click \"Enable passwordless apt\" for this server, then retry.",
				Output:  dpkgOutput,
			}
		}
		return updatePrecheckResult{
			Name:    "apt_health",
			Passed:  false,
			Details: fmt.Sprintf("dpkg audit failed: %v", dpkgErr),
			Output:  dpkgOutput,
		}
	}
	if strings.TrimSpace(dpkgStdout+dpkgStderr) != "" {
		return updatePrecheckResult{
			Name:    "apt_health",
			Passed:  false,
			Details: "dpkg audit reported package state issues.",
			Output:  dpkgOutput,
		}
	}
	aptStdout, aptStderr, aptErr := runSSHCommand(client, precheckAptCheckCmd, nil)
	aptOutput := compactCommandOutput(aptStdout, aptStderr)
	if aptErr != nil {
		if isSudoPolicyOrPasswordError(aptOutput + "\n" + aptErr.Error()) {
			return updatePrecheckResult{
				Name:    "apt_health",
				Passed:  false,
				Details: "APT health pre-check requires passwordless sudo for `/usr/bin/apt-get`. Click \"Enable passwordless apt\" for this server, then retry.",
				Output:  aptOutput,
			}
		}
		return updatePrecheckResult{
			Name:    "apt_health",
			Passed:  false,
			Details: fmt.Sprintf("apt-get check failed: %v", aptErr),
			Output:  aptOutput,
		}
	}
	return updatePrecheckResult{
		Name:    "apt_health",
		Passed:  true,
		Details: "APT health checks passed.",
		Output:  compactCommandOutput(dpkgOutput, aptOutput),
	}
}

func runUpdatePrechecks(client sshConnection) updatePrecheckSummary {
	checks := []func(sshConnection) updatePrecheckResult{
		checkDiskSpace,
		checkAptLocks,
		checkAptHealth,
	}
	summary := updatePrecheckSummary{
		AllPassed: true,
		Results:   make([]updatePrecheckResult, 0, len(checks)),
	}
	for _, check := range checks {
		result := check(client)
		summary.Results = append(summary.Results, result)
		if !result.Passed {
			summary.AllPassed = false
			summary.FailedCheck = result.Name
			return summary
		}
	}
	return summary
}

func sanitizeAuditMeta(meta map[string]any) string {
	if meta == nil {
		return "{}"
	}
	redacted := make(map[string]any, len(meta))
	for k, v := range meta {
		key := strings.ToLower(strings.TrimSpace(k))
		isPrecheckField := strings.HasPrefix(key, "precheck")
		isPassField := key == "pass" || strings.HasPrefix(key, "pass_") || strings.HasSuffix(key, "_pass")
		if (isPassField || strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "token")) && !isPrecheckField {
			continue
		}
		if !isPrecheckField && (key == "api_key" ||
			key == "access_key" ||
			key == "secret_key" ||
			key == "private_key" ||
			key == "ssh_key" ||
			key == "key" ||
			strings.HasPrefix(key, "key_") ||
			strings.HasSuffix(key, "_key") ||
			strings.HasSuffix(key, "_secret")) {
			continue
		}
		redacted[k] = v
	}
	raw, err := json.Marshal(redacted)
	if err != nil {
		return "{}"
	}
	if len(raw) > auditMetaMaxLen {
		return "{}"
	}
	return string(raw)
}

func actorFromContext(c *gin.Context) string {
	if c == nil {
		return "system"
	}
	if actor, ok := c.Get("actor"); ok {
		if s := strings.TrimSpace(fmt.Sprintf("%v", actor)); s != "" {
			return s
		}
	}
	return "unknown"
}

func clientIPFromContext(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.ClientIP())
}

func writeAuditEvent(evt AuditEvent) error {
	db := getDB()
	_, err := db.Exec(
		`INSERT INTO audit_events (created_at, actor, action, target_type, target_name, status, message, meta_json, request_id, client_ip)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		evt.CreatedAt,
		evt.Actor,
		evt.Action,
		evt.TargetType,
		evt.TargetName,
		evt.Status,
		evt.Message,
		evt.MetaJSON,
		evt.RequestID,
		evt.ClientIP,
	)
	return err
}

func auditWithActor(actor, clientIP, action, targetType, targetName, status, message string, meta map[string]any) {
	evt := AuditEvent{
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Actor:      truncateString(actor, 128),
		Action:     truncateString(action, 64),
		TargetType: truncateString(targetType, 64),
		TargetName: truncateString(targetName, 255),
		Status:     truncateString(status, 32),
		Message:    truncateString(message, auditMessageMaxLen),
		MetaJSON:   sanitizeAuditMeta(meta),
		RequestID:  "",
		ClientIP:   truncateString(clientIP, 128),
	}
	if evt.Actor == "" {
		evt.Actor = "unknown"
	}
	if evt.TargetName == "" {
		evt.TargetName = "-"
	}
	if err := writeAuditEvent(evt); err != nil {
		log.Printf("audit write failed: action=%s target=%s err=%v", action, targetName, err)
	}
}

func audit(c *gin.Context, action, targetType, targetName, status, message string, meta map[string]any) {
	auditWithActor(actorFromContext(c), clientIPFromContext(c), action, targetType, targetName, status, message, meta)
}

func pruneAuditEvents(retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	_, err := getDB().Exec("DELETE FROM audit_events WHERE created_at < ?", cutoff)
	return err
}

func startAuditPruner(ctx context.Context) {
	auditPruneTickerOnce.Do(func() {
		if err := pruneAuditEvents(auditRetentionDays); err != nil {
			log.Printf("audit prune failed: %v", err)
		}
		go func() {
			t := time.NewTicker(auditPruneInterval)
			for {
				select {
				case <-t.C:
					if err := pruneAuditEvents(auditRetentionDays); err != nil {
						log.Printf("audit prune failed: %v", err)
					}
				case <-ctx.Done():
					t.Stop()
					return
				}
			}
		}()
	})
}

func encryptSecret(secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	block, err := aes.NewCipher(getEncryptionKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
	return base64.StdEncoding.EncodeToString(nonce) + ":" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptSecret(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted value format")
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(getEncryptionKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func loadLegacyServers() bool {
	paths := []string{}
	if dirExists("/data") {
		paths = append(paths, filepath.Join("/data", legacyServersFileName))
	}
	paths = append(paths, legacyServersFileName)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var legacy []Server
		if err := json.Unmarshal(data, &legacy); err != nil {
			log.Printf("Failed to parse legacy %s: %v", path, err)
			continue
		}
		if len(legacy) == 0 {
			continue
		}
		servers = legacy
		if err := saveServersFunc(); err != nil {
			log.Printf("Failed to import legacy servers from %s: %v", path, err)
			continue
		}
		log.Printf("Imported legacy servers from %s", path)
		return true
	}
	return false
}

func loadServers() {
	db := getDB()
	rows, err := db.Query("SELECT name, host, port, user, pass_enc, key_enc, tags FROM servers ORDER BY name")
	if err != nil {
		log.Fatalf("Failed to load servers: %v", err)
	}
	defer rows.Close()

	servers = nil
	for rows.Next() {
		var name, host, user, passEnc, keyEnc, tags string
		var port int
		if err := rows.Scan(&name, &host, &port, &user, &passEnc, &keyEnc, &tags); err != nil {
			log.Fatalf("Failed to scan server row: %v", err)
		}
		pass, err := decryptSecret(passEnc)
		if err != nil {
			log.Fatalf("Failed to decrypt password for %s: %v", name, err)
		}
		key, err := decryptSecret(keyEnc)
		if err != nil {
			log.Fatalf("Failed to decrypt SSH key for %s: %v", name, err)
		}
		servers = append(servers, Server{
			Name: name,
			Host: host,
			Port: normalizePort(port),
			User: user,
			Pass: pass,
			Key:  key,
			Tags: parseTags(tags),
		})
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("Failed to read servers: %v", err)
	}

	if len(servers) == 0 {
		if !loadLegacyServers() {
			servers = []Server{
				{Name: "server1", Host: "server1.example.com", Port: 22, User: "user", Pass: "pass"},
				{Name: "server2", Host: "server2.example.com", Port: 22, User: "user", Pass: "pass"},
				{Name: "server3", Host: "server3.example.com", Port: 22, User: "user", Pass: "pass"},
				{Name: "server4", Host: "server4.example.com", Port: 22, User: "user", Pass: "pass"},
				{Name: "server5", Host: "server5.example.com", Port: 22, User: "user", Pass: "pass"},
			}
			if err := saveServersFunc(); err != nil {
				log.Fatalf("Failed to save default servers: %v", err)
			}
		}
	}
}

func saveServers() error {
	db := getDB()
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start db transaction: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM servers"); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("clear servers table: %w", err)
	}
	stmt, err := tx.Prepare("INSERT INTO servers (name, host, port, user, pass_enc, key_enc, tags) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()
	for _, server := range servers {
		enc, err := encryptSecret(server.Pass)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("encrypt password for %s: %w", server.Name, err)
		}
		keyEnc, err := encryptSecret(server.Key)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("encrypt SSH key for %s: %w", server.Name, err)
		}
		tags := joinTags(server.Tags)
		port := normalizePort(server.Port)
		if _, err := stmt.Exec(server.Name, server.Host, port, server.User, enc, keyEnc, tags); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert server %s: %w", server.Name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit servers: %w", err)
	}
	return nil
}

func saveServersOrRollbackLocked(prevServers []Server, prevStatusMap map[string]*ServerStatus) error {
	if err := saveServersFunc(); err != nil {
		servers = prevServers
		statusMap = prevStatusMap
		return err
	}
	return nil
}

func cloneServers(src []Server) []Server {
	if src == nil {
		return nil
	}
	dst := make([]Server, len(src))
	for i, server := range src {
		server.Tags = append([]string(nil), server.Tags...)
		dst[i] = server
	}
	return dst
}

func cloneStatusMap(src map[string]*ServerStatus) map[string]*ServerStatus {
	dst := make(map[string]*ServerStatus, len(src))
	for name, status := range src {
		if status == nil {
			dst[name] = nil
			continue
		}
		copyStatus := *status
		copyStatus.Upgradable = append([]string(nil), status.Upgradable...)
		copyStatus.Tags = append([]string(nil), status.Tags...)
		dst[name] = &copyStatus
	}
	return dst
}

func statusInProgress(status string) bool {
	return status == "updating" ||
		status == "pending_approval" ||
		status == "approved" ||
		status == "upgrading" ||
		status == "autoremove" ||
		status == "sudoers"
}

func findServerByNameLocked(name string) (Server, bool) {
	for _, s := range servers {
		if s.Name == name {
			return s, true
		}
	}
	return Server{}, false
}

func beginServerAction(name, newStatus string) (Server, error) {
	mu.Lock()
	defer mu.Unlock()
	status, exists := statusMap[name]
	if !exists || status == nil {
		return Server{}, sql.ErrNoRows
	}
	if statusInProgress(status.Status) {
		return Server{}, errActionInProgress
	}
	server, found := findServerByNameLocked(name)
	if !found {
		return Server{}, sql.ErrNoRows
	}
	status.Status = newStatus
	if strings.TrimSpace(status.Logs) == "" {
		status.Logs = "Starting Linux Updater..."
	}
	return server, nil
}

func readUploadedKeyData(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxUploadedKeyBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxUploadedKeyBytes {
		return "", errUploadedKeyTooLarge
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", errUploadedKeyEmpty
	}
	return key, nil
}

func readUploadedPrivateKey(file *multipart.FileHeader) (string, error) {
	if file.Size > maxUploadedKeyBytes {
		return "", errUploadedKeyTooLarge
	}
	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()
	return readUploadedKeyData(src)
}

func stringsEqualConstantTime(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func basicAuthMiddleware(username, password string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok || !stringsEqualConstantTime(user, username) || !stringsEqualConstantTime(pass, password) {
			c.Header("WWW-Authenticate", `Basic realm="SimpleLinuxUpdater"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("actor", user)
		c.Next()
	}
}

func basicAuthFromEnv() (string, string, bool, error) {
	username := strings.TrimSpace(os.Getenv(basicAuthUserEnv))
	password := os.Getenv(basicAuthPassEnv)
	if username == "" && password == "" {
		return "", "", false, nil
	}
	if username == "" || password == "" {
		return "", "", false, fmt.Errorf("%s and %s must both be set", basicAuthUserEnv, basicAuthPassEnv)
	}
	return username, password, true, nil
}

func init() {
	loadServers()
	for _, s := range servers {
		statusMap[s.Name] = &ServerStatus{
			Name:        s.Name,
			Host:        s.Host,
			Port:        normalizePort(s.Port),
			User:        s.User,
			Status:      "idle",
			Logs:        "",
			Upgradable:  []string{},
			HasPassword: s.Pass != "",
			HasKey:      s.Key != "",
			Tags:        s.Tags,
		}
	}
}

func runUpdate(server Server) {
	retryPolicy := loadRetryPolicyFromEnv()
	runUpdateWithActor(server, "system", "", retryPolicy)
}

type withActorRunner struct {
	server   Server
	actor    string
	clientIP string
	policy   RetryPolicy

	config *ssh.ClientConfig
	client sshConnection

	sshDialAttempts        int
	aptUpdateAttempts      int
	listUpgradableAttempts int
	aptUpgradeAttempts     int
	commandAttempts        int

	retryExhausted bool
	lastErrClass   string

	prechecksPassed bool
	precheckFailed  string
	precheckResults []updatePrecheckResult
}

func (r *withActorRunner) withStatus(update func(*ServerStatus)) bool {
	mu.Lock()
	defer mu.Unlock()
	status := statusMap[r.server.Name]
	if status == nil {
		return false
	}
	update(status)
	return true
}

func (r *withActorRunner) appendStatusLog(line string) {
	_ = r.withStatus(func(status *ServerStatus) {
		status.Logs += line
	})
}

func (r *withActorRunner) setErrorLogs(logs string) {
	_ = r.withStatus(func(status *ServerStatus) {
		status.Status = "error"
		status.Logs = logs
	})
}

func (r *withActorRunner) currentLogs() string {
	mu.Lock()
	defer mu.Unlock()
	if status := statusMap[r.server.Name]; status != nil {
		return status.Logs
	}
	return ""
}

func (r *withActorRunner) markErrorClass(err error) {
	if isRetryableError(err) {
		r.lastErrClass = "transient"
		r.retryExhausted = true
		return
	}
	r.lastErrClass = "permanent"
}

func (r *withActorRunner) setupSSH(dialOpName string) bool {
	authMethods, err := buildAuthMethods(r.server)
	if err != nil {
		r.lastErrClass = "permanent"
		r.setErrorLogs(fmt.Sprintf("Auth setup failed: %v", err))
		return false
	}
	hostKeyCallback, err := getHostKeyCallback()
	if err != nil {
		r.lastErrClass = "permanent"
		r.setErrorLogs(fmt.Sprintf("Host key verification setup failed: %v", err))
		return false
	}
	r.config = &ssh.ClientConfig{
		User:            r.server.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}
	client, err := dialSSHWithRetry(r.server, r.config, r.policy, dialOpName, &r.sshDialAttempts)
	if err != nil {
		r.markErrorClass(err)
		r.setErrorLogs(fmt.Sprintf("SSH connection failed: %v", err))
		return false
	}
	r.client = client
	return true
}

func runWithActorShared(
	server Server,
	actor, clientIP string,
	policy RetryPolicy,
	auditAction string,
	initStatus func(*ServerStatus, RetryPolicy),
	auditMeta func(*withActorRunner, string) map[string]any,
	outcomeForStatus func(string) string,
	dialOpName string,
	runSteps func(*withActorRunner),
) {
	runner := &withActorRunner{
		server:       server,
		actor:        actor,
		clientIP:     clientIP,
		policy:       policy,
		lastErrClass: "none",
	}
	if auditMeta == nil {
		auditMeta = func(*withActorRunner, string) map[string]any { return map[string]any{} }
	}
	if outcomeForStatus == nil {
		outcomeForStatus = updateCompletionOutcome
	}

	defer func() {
		mu.Lock()
		finalStatus := "unknown"
		if status := statusMap[server.Name]; status != nil {
			finalStatus = status.Status
		}
		mu.Unlock()
		outcome := outcomeForStatus(finalStatus)
		auditWithActor(
			actor,
			clientIP,
			auditAction,
			"server",
			server.Name,
			outcome,
			fmt.Sprintf("Final status: %s", finalStatus),
			auditMeta(runner, finalStatus),
		)
	}()

	if !runner.withStatus(func(status *ServerStatus) {
		initStatus(status, policy)
	}) {
		return
	}

	if !runner.setupSSH(dialOpName) {
		return
	}
	defer func() {
		if runner.client != nil {
			_ = runner.client.Close()
		}
	}()

	runSteps(runner)
}

func doneOnlyOutcome(finalStatus string) string {
	if finalStatus == "done" {
		return "success"
	}
	return "failure"
}

func updateRunnerAuditMeta(r *withActorRunner, finalStatus string) map[string]any {
	return map[string]any{
		"status":                        finalStatus,
		"ssh_dial_attempts_used":        r.sshDialAttempts,
		"apt_update_attempts_used":      r.aptUpdateAttempts,
		"list_upgradable_attempts_used": r.listUpgradableAttempts,
		"apt_upgrade_attempts_used":     r.aptUpgradeAttempts,
		"total_attempts_used":           r.sshDialAttempts + r.aptUpdateAttempts + r.listUpgradableAttempts + r.aptUpgradeAttempts,
		"last_error_class":              r.lastErrClass,
		"retry_exhausted":               r.retryExhausted,
		"prechecks_passed":              r.prechecksPassed,
		"precheck_failed":               r.precheckFailed,
		"precheck_results":              r.precheckResults,
	}
}

func commandRunnerAuditMeta(r *withActorRunner, finalStatus string) map[string]any {
	return map[string]any{
		"status":                 finalStatus,
		"ssh_dial_attempts_used": r.sshDialAttempts,
		"command_attempts_used":  r.commandAttempts,
		"total_attempts_used":    r.sshDialAttempts + r.commandAttempts,
		"last_error_class":       r.lastErrClass,
		"retry_exhausted":        r.retryExhausted,
	}
}

func runUpdateWithActor(server Server, actor, clientIP string, policy RetryPolicy) {
	runWithActorShared(
		server,
		actor,
		clientIP,
		policy,
		"update.complete",
		func(status *ServerStatus, policy RetryPolicy) {
			status.Status = "updating"
			status.Upgradable = nil
			status.Logs = fmt.Sprintf(
				"Starting Linux Updater...\nRetries enabled: max_attempts=%d base_delay=%s max_delay=%s jitter=%d%%",
				policy.MaxAttempts,
				policy.BaseDelay,
				policy.MaxDelay,
				policy.JitterPct,
			)
		},
		updateRunnerAuditMeta,
		updateCompletionOutcome,
		"update.ssh_dial",
		func(r *withActorRunner) {
			r.appendStatusLog("\nRunning pre-checks...")

			precheckSummary := runUpdatePrechecks(r.client)
			r.precheckResults = precheckSummary.Results
			for _, result := range precheckSummary.Results {
				state := "PASS"
				if !result.Passed {
					state = "FAIL"
				}
				line := fmt.Sprintf("\nPre-check %s [%s]: %s", result.Name, state, result.Details)
				if trimmed := strings.TrimSpace(result.Output); trimmed != "" {
					line += fmt.Sprintf(" Output: %s", trimmed)
				}
				r.appendStatusLog(line)
			}
			if !precheckSummary.AllPassed {
				r.lastErrClass = "permanent"
				r.precheckFailed = precheckSummary.FailedCheck
				_ = r.withStatus(func(status *ServerStatus) {
					status.Status = "error"
					status.Logs += fmt.Sprintf("\nPre-check failed (%s). Update aborted before apt update.", precheckSummary.FailedCheck)
				})
				return
			}
			r.prechecksPassed = true
			_ = r.withStatus(func(status *ServerStatus) {
				status.Logs += "\nPre-checks passed.\nRunning apt update..."
			})

			var stdout, stderr bytes.Buffer
			err := runSSHOperationWithRetry(
				r.server,
				r.config,
				&r.client,
				r.policy,
				"update.apt_update",
				"\napt update attempt %d/%d failed: %v; retrying in %s",
				&r.aptUpdateAttempts,
				func() error {
					session, sessionErr := r.client.NewSession()
					if sessionErr != nil {
						return sessionErr
					}
					defer session.Close()
					stdout.Reset()
					stderr.Reset()
					session.SetStdout(&stdout)
					session.SetStderr(&stderr)
					runErr := session.Run("sudo apt update")
					return markRetryableFromOutput(runErr, stdout.String()+"\n"+stderr.String())
				},
			)
			logs := r.currentLogs() + "\n" + stdout.String() + stderr.String()
			if err != nil {
				r.markErrorClass(err)
				logs += fmt.Sprintf("\nError: %v", err)
				r.setErrorLogs(logs)
				return
			}

			var upgradable []string
			err = runSSHOperationWithRetry(
				r.server,
				r.config,
				&r.client,
				r.policy,
				"update.list_upgradable",
				"\nlist upgradable attempt %d/%d failed: %v; retrying in %s",
				&r.listUpgradableAttempts,
				func() error {
					items, listErr := getUpgradable(r.client)
					if listErr == nil {
						upgradable = items
					}
					return listErr
				},
			)
			if err != nil {
				r.markErrorClass(err)
				r.setErrorLogs(logs + fmt.Sprintf("\nError listing upgradable: %v", err))
				return
			}

			if len(upgradable) == 0 {
				_ = r.withStatus(func(status *ServerStatus) {
					status.Status = "done"
					status.Logs = logs + "\nNo packages to upgrade."
				})
				return
			}

			_ = r.withStatus(func(status *ServerStatus) {
				status.Status = "pending_approval"
				status.Upgradable = upgradable
				status.Logs = logs + "\nUpgradable packages:\n" + strings.Join(upgradable, "\n")
			})

			approvalDeadline := time.Now().Add(30 * time.Minute)
			for {
				time.Sleep(1 * time.Second)
				approved := false
				cancelledOrTimeout := false
				mu.Lock()
				status := statusMap[r.server.Name]
				if status != nil {
					if status.Status == "approved" {
						approved = true
					} else if status.Status == "cancelled" || time.Now().After(approvalDeadline) {
						status.Status = "idle"
						status.Logs = ""
						status.Upgradable = nil
						cancelledOrTimeout = true
					}
				}
				mu.Unlock()
				if approved {
					break
				}
				if cancelledOrTimeout {
					return
				}
			}

			_ = r.withStatus(func(status *ServerStatus) {
				status.Status = "upgrading"
				status.Logs += "\nRunning apt upgrade..."
			})

			stdout.Reset()
			stderr.Reset()
			err = runSSHOperationWithRetry(
				r.server,
				r.config,
				&r.client,
				r.policy,
				"update.apt_upgrade",
				"\napt upgrade attempt %d/%d failed: %v; retrying in %s",
				&r.aptUpgradeAttempts,
				func() error {
					session, sessionErr := r.client.NewSession()
					if sessionErr != nil {
						return sessionErr
					}
					defer session.Close()
					stdout.Reset()
					stderr.Reset()
					session.SetStdout(&stdout)
					session.SetStderr(&stderr)
					runErr := session.Run("sudo apt upgrade -y")
					return markRetryableFromOutput(runErr, stdout.String()+"\n"+stderr.String())
				},
			)
			logs = r.currentLogs() + "\n" + stdout.String() + stderr.String()
			if err != nil {
				r.markErrorClass(err)
				logs += fmt.Sprintf("\nError: %v", err)
				r.setErrorLogs(logs)
				return
			}

			_ = r.withStatus(func(status *ServerStatus) {
				status.Status = "done"
				status.Logs = logs + "\nUpgrade completed."
			})
		},
	)
}

func runSudoersBootstrap(server Server, sudoPassword string) {
	retryPolicy := loadRetryPolicyFromEnv()
	runSudoersBootstrapWithActor(server, sudoPassword, "system", "", retryPolicy)
}

func runSudoersBootstrapWithActor(server Server, sudoPassword, actor, clientIP string, policy RetryPolicy) {
	runWithActorShared(
		server,
		actor,
		clientIP,
		policy,
		"sudoers.enable.complete",
		func(status *ServerStatus, policy RetryPolicy) {
			status.Status = "sudoers"
			if strings.TrimSpace(status.Logs) == "" {
				status.Logs = "Starting Linux Updater..."
			}
			status.Logs += fmt.Sprintf(
				"\nRetries enabled: max_attempts=%d base_delay=%s max_delay=%s jitter=%d%%\nConfiguring passwordless apt sudoers...",
				policy.MaxAttempts,
				policy.BaseDelay,
				policy.MaxDelay,
				policy.JitterPct,
			)
		},
		commandRunnerAuditMeta,
		doneOnlyOutcome,
		"sudoers.enable.ssh_dial",
		func(r *withActorRunner) {
			line := fmt.Sprintf("%s ALL=(root) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg, /usr/bin/fuser", r.server.User)
			escapedLine := shellEscapeDoubleQuotes(line)
			cmd := fmt.Sprintf("sudo -S -p '' sh -c \"printf '%%s\\n' '%s' > /etc/sudoers.d/apt-nopasswd && chmod 440 /etc/sudoers.d/apt-nopasswd && /usr/sbin/visudo -cf /etc/sudoers.d/apt-nopasswd\"", escapedLine)

			var stdout, stderr bytes.Buffer
			err := runSSHOperationWithRetry(
				r.server,
				r.config,
				&r.client,
				r.policy,
				"sudoers.enable.command",
				"\nsudoers enable attempt %d/%d failed: %v; retrying in %s",
				&r.commandAttempts,
				func() error {
					session, sessionErr := r.client.NewSession()
					if sessionErr != nil {
						return sessionErr
					}
					defer session.Close()
					stdout.Reset()
					stderr.Reset()
					session.SetStdout(&stdout)
					session.SetStderr(&stderr)
					session.SetStdin(strings.NewReader(sudoPassword + "\n"))
					return session.Run(cmd)
				},
			)
			logs := r.currentLogs() + "\n" + stdout.String() + stderr.String()
			if err != nil {
				r.markErrorClass(err)
				logs += fmt.Sprintf("\nError: %v", err)
				r.setErrorLogs(logs)
				return
			}
			_ = r.withStatus(func(status *ServerStatus) {
				status.Status = "done"
				status.Logs = logs + "\nPasswordless apt sudoers enabled."
			})
		},
	)
}

func runSudoersDisable(server Server, sudoPassword string) {
	retryPolicy := loadRetryPolicyFromEnv()
	runSudoersDisableWithActor(server, sudoPassword, "system", "", retryPolicy)
}

func runSudoersDisableWithActor(server Server, sudoPassword, actor, clientIP string, policy RetryPolicy) {
	runWithActorShared(
		server,
		actor,
		clientIP,
		policy,
		"sudoers.disable.complete",
		func(status *ServerStatus, policy RetryPolicy) {
			status.Status = "sudoers"
			if strings.TrimSpace(status.Logs) == "" {
				status.Logs = "Starting Linux Updater..."
			}
			status.Logs += fmt.Sprintf(
				"\nRetries enabled: max_attempts=%d base_delay=%s max_delay=%s jitter=%d%%\nDisabling passwordless apt sudoers...",
				policy.MaxAttempts,
				policy.BaseDelay,
				policy.MaxDelay,
				policy.JitterPct,
			)
		},
		commandRunnerAuditMeta,
		doneOnlyOutcome,
		"sudoers.disable.ssh_dial",
		func(r *withActorRunner) {
			cmd := "sudo -S -p '' rm -f /etc/sudoers.d/apt-nopasswd"

			var stdout, stderr bytes.Buffer
			err := runSSHOperationWithRetry(
				r.server,
				r.config,
				&r.client,
				r.policy,
				"sudoers.disable.command",
				"\nsudoers disable attempt %d/%d failed: %v; retrying in %s",
				&r.commandAttempts,
				func() error {
					session, sessionErr := r.client.NewSession()
					if sessionErr != nil {
						return sessionErr
					}
					defer session.Close()
					stdout.Reset()
					stderr.Reset()
					session.SetStdout(&stdout)
					session.SetStderr(&stderr)
					session.SetStdin(strings.NewReader(sudoPassword + "\n"))
					return session.Run(cmd)
				},
			)
			logs := r.currentLogs() + "\n" + stdout.String() + stderr.String()
			if err != nil {
				r.markErrorClass(err)
				logs += fmt.Sprintf("\nError: %v", err)
				r.setErrorLogs(logs)
				return
			}
			_ = r.withStatus(func(status *ServerStatus) {
				status.Status = "done"
				status.Logs = logs + "\nPasswordless apt sudoers disabled."
			})
		},
	)
}

func runAutoremove(server Server) {
	retryPolicy := loadRetryPolicyFromEnv()
	runAutoremoveWithActor(server, "system", "", retryPolicy)
}

func runAutoremoveWithActor(server Server, actor, clientIP string, policy RetryPolicy) {
	runWithActorShared(
		server,
		actor,
		clientIP,
		policy,
		"autoremove.complete",
		func(status *ServerStatus, policy RetryPolicy) {
			status.Status = "autoremove"
			if strings.TrimSpace(status.Logs) == "" {
				status.Logs = "Starting Linux Updater..."
			}
			status.Logs += fmt.Sprintf(
				"\nRetries enabled: max_attempts=%d base_delay=%s max_delay=%s jitter=%d%%\nRunning apt autoremove...",
				policy.MaxAttempts,
				policy.BaseDelay,
				policy.MaxDelay,
				policy.JitterPct,
			)
		},
		commandRunnerAuditMeta,
		doneOnlyOutcome,
		"autoremove.ssh_dial",
		func(r *withActorRunner) {
			var stdout, stderr bytes.Buffer
			err := runSSHOperationWithRetry(
				r.server,
				r.config,
				&r.client,
				r.policy,
				"autoremove.command",
				"\nautoremove attempt %d/%d failed: %v; retrying in %s",
				&r.commandAttempts,
				func() error {
					session, sessionErr := r.client.NewSession()
					if sessionErr != nil {
						return sessionErr
					}
					defer session.Close()
					stdout.Reset()
					stderr.Reset()
					session.SetStdout(&stdout)
					session.SetStderr(&stderr)
					runErr := session.Run("sudo apt autoremove -y")
					return markRetryableFromOutput(runErr, stdout.String()+"\n"+stderr.String())
				},
			)
			logs := r.currentLogs() + "\n" + stdout.String() + stderr.String()
			if err != nil {
				r.markErrorClass(err)
				logs += fmt.Sprintf("\nError: %v", err)
				r.setErrorLogs(logs)
				return
			}
			_ = r.withStatus(func(status *ServerStatus) {
				status.Status = "done"
				status.Logs = logs + "\nAutoremove completed."
			})
		},
	)
}

func getUpgradable(client sshConnection) ([]string, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	var stdout bytes.Buffer
	session.SetStdout(&stdout)
	err = session.Run("apt list --upgradable")
	if err != nil {
		return nil, err
	}
	output := stdout.String()
	lines := strings.Split(output, "\n")
	var upgradable []string
	for _, line := range lines[1:] { // skip header
		if strings.TrimSpace(line) != "" {
			upgradable = append(upgradable, line)
		}
	}
	return upgradable, nil
}

func getGlobalKey() string {
	db := getDB()
	for attempt := 1; attempt <= 3; attempt++ {
		var enc string
		err := db.QueryRow("SELECT value FROM settings WHERE key = ?", globalKeySetting).Scan(&enc)
		if err == sql.ErrNoRows {
			globalKeyMu.Lock()
			globalKey = ""
			globalKeyMu.Unlock()
			return ""
		}
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "database is locked") && attempt < 3 {
				time.Sleep(75 * time.Millisecond)
				continue
			}
			globalKeyMu.RLock()
			cached := globalKey
			globalKeyMu.RUnlock()
			log.Printf("Failed to load global SSH key: %v", err)
			if strings.TrimSpace(cached) != "" {
				log.Printf("Using cached global SSH key due to read failure")
			}
			return cached
		}
		key, decErr := decryptSecret(enc)
		if decErr != nil {
			globalKeyMu.RLock()
			cached := globalKey
			globalKeyMu.RUnlock()
			log.Printf("Failed to decrypt global SSH key: %v", decErr)
			if strings.TrimSpace(cached) != "" {
				log.Printf("Using cached global SSH key due to decrypt failure")
			}
			return cached
		}
		globalKeyMu.Lock()
		globalKey = key
		globalKeyMu.Unlock()
		return key
	}
	return ""
}

func setGlobalKey(key string) error {
	enc, err := encryptSecret(key)
	if err != nil {
		return err
	}
	db := getDB()
	_, err = db.Exec(
		"INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		globalKeySetting, enc,
	)
	if err != nil {
		return err
	}
	globalKeyMu.Lock()
	globalKey = key
	globalKeyMu.Unlock()
	return nil
}

func clearGlobalKey() error {
	db := getDB()
	if _, err := db.Exec("DELETE FROM settings WHERE key = ?", globalKeySetting); err != nil {
		return err
	}
	globalKeyMu.Lock()
	globalKey = ""
	globalKeyMu.Unlock()
	return nil
}

func updateServerKey(name, key string) error {
	enc, err := encryptSecret(key)
	if err != nil {
		return err
	}
	db := getDB()
	_, err = db.Exec("UPDATE servers SET key_enc = ? WHERE name = ?", enc, name)
	return err
}

func parseTags(raw string) []string {
	parts := strings.Split(raw, ",")
	var tags []string
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func joinTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	cleaned := make([]string, 0, len(tags))
	seen := make(map[string]struct{})
	for _, tag := range tags {
		clean := strings.TrimSpace(tag)
		if clean == "" {
			continue
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		cleaned = append(cleaned, clean)
	}
	return strings.Join(cleaned, ", ")
}

func normalizePort(port int) int {
	if port <= 0 || port > 65535 {
		return 22
	}
	return port
}

func normalizeServerName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeServerHost(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func serverNameExistsLocked(name string, skipIndex int) bool {
	normalized := normalizeServerName(name)
	for i, existing := range servers {
		if i == skipIndex {
			continue
		}
		if normalizeServerName(existing.Name) == normalized {
			return true
		}
	}
	return false
}

func serverHostExistsLocked(host string, skipIndex int) bool {
	normalized := normalizeServerHost(host)
	for i, existing := range servers {
		if i == skipIndex {
			continue
		}
		if normalizeServerHost(existing.Host) == normalized {
			return true
		}
	}
	return false
}

func knownHostsPaths() []string {
	if raw := strings.TrimSpace(os.Getenv("DEBIAN_UPDATER_KNOWN_HOSTS")); raw != "" {
		parts := strings.Split(raw, ":")
		paths := make([]string, 0, len(parts))
		for _, part := range parts {
			path := strings.TrimSpace(part)
			if path != "" {
				paths = append(paths, path)
			}
		}
		return paths
	}
	paths := []string{filepath.Join(filepath.Dir(dbPath()), "known_hosts")}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		paths = append(paths, filepath.Join(home, ".ssh", "known_hosts"))
	}
	paths = append(paths, "/etc/ssh/ssh_known_hosts")
	seen := make(map[string]struct{}, len(paths))
	unique := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		unique = append(unique, path)
	}
	return unique
}

func getHostKeyCallback() (ssh.HostKeyCallback, error) {
	candidates := knownHostsPaths()
	existing := make([]string, 0, len(candidates))
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}
	if len(existing) == 0 {
		return nil, errors.New("no known_hosts file found; set DEBIAN_UPDATER_KNOWN_HOSTS or create ~/.ssh/known_hosts")
	}
	cb, err := knownhosts.New(existing...)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return cb, nil
}

func knownHostsWritePath() (string, error) {
	paths := knownHostsPaths()
	if len(paths) == 0 {
		return "", errors.New("no known_hosts path configured")
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return paths[0], nil
}

func knownHostsHostToken(host string, port int) string {
	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	if normalizePort(port) == 22 {
		return cleanHost
	}
	return fmt.Sprintf("[%s]:%d", cleanHost, normalizePort(port))
}

func appendKnownHostLine(line string) error {
	cleanLine := strings.TrimSpace(line)
	if cleanLine == "" {
		return errors.New("empty known_hosts line")
	}
	path, err := knownHostsWritePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create known_hosts dir: %w", err)
	}

	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read known_hosts: %w", err)
	}
	if strings.Contains("\n"+string(data)+"\n", "\n"+cleanLine+"\n") {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open known_hosts for append: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(cleanLine + "\n"); err != nil {
		return fmt.Errorf("append known_hosts line: %w", err)
	}
	return nil
}

func scanHostKey(host string, port int) (ssh.PublicKey, error) {
	cleanHost := strings.TrimSpace(host)
	if cleanHost == "" {
		return nil, errors.New("host is required")
	}
	address := net.JoinHostPort(cleanHost, strconv.Itoa(normalizePort(port)))
	var scanned ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "hostkey-scan",
		Auth: []ssh.AuthMethod{
			ssh.Password("invalid"),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			scanned = key
			return nil
		},
		Timeout: sshConnectTimeout,
	}
	client, err := ssh.Dial("tcp", address, cfg)
	if client != nil {
		_ = client.Close()
	}
	if err != nil {
		msg := strings.ToLower(err.Error())
		isAuthErr := strings.Contains(msg, "unable to authenticate") ||
			strings.Contains(msg, "no auth") ||
			strings.Contains(msg, "permission denied") ||
			strings.Contains(msg, "authentication")
		if scanned != nil && isAuthErr {
			return scanned, nil
		}
		return nil, err
	}
	if scanned != nil {
		return scanned, nil
	}
	return nil, errors.New("unable to scan host key")
}

func buildKnownHostsLine(host string, port int, key ssh.PublicKey) string {
	return knownhosts.Line([]string{knownHostsHostToken(host, port)}, key)
}

func trustHostKey(host string, port int, expectedFingerprint string) (string, string, error) {
	key, err := scanHostKeyFunc(host, port)
	if err != nil {
		return "", "", err
	}
	fingerprint := ssh.FingerprintSHA256(key)
	if strings.TrimSpace(expectedFingerprint) != "" && !stringsEqualConstantTime(fingerprint, strings.TrimSpace(expectedFingerprint)) {
		return "", "", errFingerprintMismatch
	}
	line := buildKnownHostsLine(host, port, key)
	if err := appendKnownHostLine(line); err != nil {
		return "", "", err
	}
	return fingerprint, line, nil
}

func shellEscapeSingleQuotes(input string) string {
	return strings.ReplaceAll(input, "'", "'\"'\"'")
}

func shellEscapeDoubleQuotes(input string) string {
	escaped := strings.ReplaceAll(input, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, `$`, `\$`)
	escaped = strings.ReplaceAll(escaped, "`", "\\`")
	return escaped
}

func isValidSSHUsername(username string) bool {
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

func buildAuthMethods(server Server) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	key := strings.TrimSpace(server.Key)
	if key == "" {
		key = strings.TrimSpace(getGlobalKey())
	}
	if key != "" {
		signer, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if server.Pass != "" {
		methods = append(methods, ssh.Password(server.Pass))
	}
	if len(methods) == 0 {
		return nil, errors.New("missing password or SSH key")
	}
	return methods, nil
}

func main() {
	r := gin.Default()
	username, password, basicAuthEnabled, err := basicAuthFromEnv()
	if err != nil {
		log.Fatalf("Invalid basic auth configuration: %v", err)
	}
	if basicAuthEnabled {
		r.Use(basicAuthMiddleware(username, password))
		log.Printf("Basic auth enabled from %s/%s", basicAuthUserEnv, basicAuthPassEnv)
	} else {
		log.Printf("Basic auth is disabled (set %s and %s to enable it)", basicAuthUserEnv, basicAuthPassEnv)
	}
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")
	startAuditPruner(context.Background())

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.GET("/manage", func(c *gin.Context) {
		c.HTML(http.StatusOK, "manage.html", nil)
	})

	r.GET("/api/servers", func(c *gin.Context) {
		mu.Lock()
		var statuses []ServerStatus
		for _, s := range servers {
			status := statusMap[s.Name]
			if status == nil {
				continue
			}
			status.Host = s.Host
			status.Port = normalizePort(s.Port)
			status.User = s.User
			status.HasPassword = s.Pass != ""
			status.HasKey = s.Key != ""
			status.Tags = s.Tags
			statuses = append(statuses, *status)
		}
		mu.Unlock()
		c.JSON(http.StatusOK, statuses)
	})

	r.POST("/api/servers", func(c *gin.Context) {
		var newServer Server
		if err := c.ShouldBindJSON(&newServer); err != nil {
			audit(c, "server.create", "server", "-", "failure", "Invalid request payload", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		newServer.Name = strings.TrimSpace(newServer.Name)
		newServer.Host = strings.TrimSpace(newServer.Host)
		newServer.User = strings.TrimSpace(newServer.User)
		if newServer.Name == "" || newServer.Host == "" || newServer.User == "" {
			audit(c, "server.create", "server", newServer.Name, "failure", "Missing required fields", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": "name, host, and user are required"})
			return
		}
		if !isValidSSHUsername(newServer.User) {
			audit(c, "server.create", "server", newServer.Name, "failure", "Invalid SSH username", map[string]any{"user": newServer.User})
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user; allowed characters are letters, digits, '.', '-', '_'"})
			return
		}
		newServer.Port = normalizePort(newServer.Port)
		newServer.Tags = parseTags(joinTags(newServer.Tags))
		mu.Lock()
		prevServers := cloneServers(servers)
		prevStatusMap := cloneStatusMap(statusMap)
		if serverNameExistsLocked(newServer.Name, -1) {
			mu.Unlock()
			audit(c, "server.create", "server", newServer.Name, "failure", "Server name already exists", nil)
			c.JSON(http.StatusConflict, gin.H{"error": "Server name already exists"})
			return
		}
		if serverHostExistsLocked(newServer.Host, -1) {
			mu.Unlock()
			audit(c, "server.create", "server", newServer.Name, "failure", "Server host already exists", map[string]any{"host": newServer.Host})
			c.JSON(http.StatusConflict, gin.H{"error": "Server host already exists"})
			return
		}
		servers = append(servers, newServer)
		statusMap[newServer.Name] = &ServerStatus{
			Name:        newServer.Name,
			Host:        newServer.Host,
			Port:        normalizePort(newServer.Port),
			User:        newServer.User,
			Status:      "idle",
			Logs:        "",
			Upgradable:  []string{},
			HasPassword: newServer.Pass != "",
			HasKey:      newServer.Key != "",
			Tags:        newServer.Tags,
		}
		if err := saveServersOrRollbackLocked(prevServers, prevStatusMap); err != nil {
			mu.Unlock()
			audit(c, "server.create", "server", newServer.Name, "failure", "Failed to persist server", map[string]any{"error": err.Error()})
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save servers: %v", err)})
			return
		}
		mu.Unlock()
		audit(c, "server.create", "server", newServer.Name, "success", "Server created", map[string]any{"host": newServer.Host, "port": newServer.Port, "tags_count": len(newServer.Tags)})
		c.JSON(http.StatusCreated, newServer)
	})

	r.PUT("/api/servers/:name", func(c *gin.Context) {
		name := c.Param("name")
		var updatedServer Server
		if err := c.ShouldBindJSON(&updatedServer); err != nil {
			audit(c, "server.update", "server", name, "failure", "Invalid request payload", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updatedServer.Name = strings.TrimSpace(updatedServer.Name)
		updatedServer.Host = strings.TrimSpace(updatedServer.Host)
		updatedServer.User = strings.TrimSpace(updatedServer.User)
		if updatedServer.Name == "" || updatedServer.Host == "" || updatedServer.User == "" {
			audit(c, "server.update", "server", name, "failure", "Missing required fields", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": "name, host, and user are required"})
			return
		}
		if !isValidSSHUsername(updatedServer.User) {
			audit(c, "server.update", "server", name, "failure", "Invalid SSH username", map[string]any{"user": updatedServer.User})
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user; allowed characters are letters, digits, '.', '-', '_'"})
			return
		}
		mu.Lock()
		prevServers := cloneServers(servers)
		prevStatusMap := cloneStatusMap(statusMap)
		for i, s := range servers {
			if s.Name == name {
				if strings.TrimSpace(updatedServer.Pass) == "" {
					updatedServer.Pass = s.Pass
				}
				if strings.TrimSpace(updatedServer.Key) == "" {
					updatedServer.Key = s.Key
				}
				if updatedServer.Port == 0 {
					updatedServer.Port = s.Port
				}
				updatedServer.Port = normalizePort(updatedServer.Port)
				if updatedServer.Tags == nil {
					updatedServer.Tags = s.Tags
				}
				updatedServer.Tags = parseTags(joinTags(updatedServer.Tags))
				if serverNameExistsLocked(updatedServer.Name, i) {
					mu.Unlock()
					audit(c, "server.update", "server", name, "failure", "Server name already exists", nil)
					c.JSON(http.StatusConflict, gin.H{"error": "Server name already exists"})
					return
				}
				if serverHostExistsLocked(updatedServer.Host, i) {
					mu.Unlock()
					audit(c, "server.update", "server", name, "failure", "Server host already exists", map[string]any{"host": updatedServer.Host})
					c.JSON(http.StatusConflict, gin.H{"error": "Server host already exists"})
					return
				}
				servers[i] = updatedServer
				if updatedServer.Name != name {
					delete(statusMap, name)
					statusMap[updatedServer.Name] = &ServerStatus{
						Name:        updatedServer.Name,
						Host:        updatedServer.Host,
						Port:        normalizePort(updatedServer.Port),
						User:        updatedServer.User,
						Status:      "idle",
						Logs:        "",
						Upgradable:  []string{},
						HasPassword: updatedServer.Pass != "",
						HasKey:      updatedServer.Key != "",
						Tags:        updatedServer.Tags,
					}
				} else {
					if statusMap[name] == nil {
						statusMap[name] = &ServerStatus{
							Name:       updatedServer.Name,
							Status:     "idle",
							Upgradable: []string{},
						}
					}
					statusMap[name].Host = updatedServer.Host
					statusMap[name].Port = normalizePort(updatedServer.Port)
					statusMap[name].User = updatedServer.User
					statusMap[name].HasPassword = updatedServer.Pass != ""
					statusMap[name].HasKey = updatedServer.Key != ""
					statusMap[name].Tags = updatedServer.Tags
				}
				if err := saveServersOrRollbackLocked(prevServers, prevStatusMap); err != nil {
					mu.Unlock()
					audit(c, "server.update", "server", name, "failure", "Failed to persist server", map[string]any{"error": err.Error()})
					c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save servers: %v", err)})
					return
				}
				mu.Unlock()
				audit(c, "server.update", "server", updatedServer.Name, "success", "Server updated", map[string]any{"from": name, "host": updatedServer.Host, "port": updatedServer.Port, "tags_count": len(updatedServer.Tags)})
				c.JSON(http.StatusOK, updatedServer)
				return
			}
		}
		mu.Unlock()
		audit(c, "server.update", "server", name, "failure", "Server not found", nil)
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.DELETE("/api/servers/:name", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		prevServers := cloneServers(servers)
		prevStatusMap := cloneStatusMap(statusMap)
		for i, s := range servers {
			if s.Name == name {
				servers = append(servers[:i], servers[i+1:]...)
				delete(statusMap, name)
				if err := saveServersOrRollbackLocked(prevServers, prevStatusMap); err != nil {
					mu.Unlock()
					audit(c, "server.delete", "server", name, "failure", "Failed to persist deletion", map[string]any{"error": err.Error()})
					c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save servers: %v", err)})
					return
				}
				mu.Unlock()
				audit(c, "server.delete", "server", name, "success", "Server deleted", nil)
				c.JSON(http.StatusOK, gin.H{"message": "Server deleted"})
				return
			}
		}
		mu.Unlock()
		audit(c, "server.delete", "server", name, "failure", "Server not found", nil)
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.DELETE("/api/servers/:name/password", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		defer mu.Unlock()
		prevServers := cloneServers(servers)
		prevStatusMap := cloneStatusMap(statusMap)
		for i, s := range servers {
			if s.Name == name {
				servers[i].Pass = ""
				if err := saveServersOrRollbackLocked(prevServers, prevStatusMap); err != nil {
					audit(c, "server.password.clear", "server", name, "failure", "Failed to persist password clear", map[string]any{"error": err.Error()})
					c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save servers: %v", err)})
					return
				}
				if status, ok := statusMap[name]; ok {
					status.HasPassword = false
				}
				audit(c, "server.password.clear", "server", name, "success", "Password cleared", nil)
				c.JSON(http.StatusOK, gin.H{"message": "Password cleared"})
				return
			}
		}
		audit(c, "server.password.clear", "server", name, "failure", "Server not found", nil)
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.POST("/api/servers/:name/key", func(c *gin.Context) {
		name := c.Param("name")
		file, err := c.FormFile("key")
		if err != nil {
			audit(c, "server.key.upload", "server", name, "failure", "Missing key file", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing key file"})
			return
		}
		key, err := readUploadedPrivateKey(file)
		if err != nil {
			if errors.Is(err, errUploadedKeyTooLarge) {
				audit(c, "server.key.upload", "server", name, "failure", "Uploaded key too large", nil)
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
				return
			}
			if errors.Is(err, errUploadedKeyEmpty) {
				audit(c, "server.key.upload", "server", name, "failure", "Uploaded key empty", nil)
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			audit(c, "server.key.upload", "server", name, "failure", "Failed to read key", nil)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read key"})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for i, s := range servers {
			if s.Name == name {
				servers[i].Key = key
				if err := updateServerKey(name, key); err != nil {
					audit(c, "server.key.upload", "server", name, "failure", "Failed to save key", map[string]any{"error": err.Error()})
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				if status, ok := statusMap[name]; ok {
					status.HasKey = key != ""
				}
				audit(c, "server.key.upload", "server", name, "success", "SSH key uploaded", nil)
				c.JSON(http.StatusOK, gin.H{"message": "Key uploaded"})
				return
			}
		}
		audit(c, "server.key.upload", "server", name, "failure", "Server not found", nil)
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.DELETE("/api/servers/:name/key", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		defer mu.Unlock()
		for i, s := range servers {
			if s.Name == name {
				servers[i].Key = ""
				if err := updateServerKey(name, ""); err != nil {
					audit(c, "server.key.clear", "server", name, "failure", "Failed to clear key", map[string]any{"error": err.Error()})
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				if status, ok := statusMap[name]; ok {
					status.HasKey = false
				}
				audit(c, "server.key.clear", "server", name, "success", "SSH key cleared", nil)
				c.JSON(http.StatusOK, gin.H{"message": "Key cleared"})
				return
			}
		}
		audit(c, "server.key.clear", "server", name, "failure", "Server not found", nil)
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
	})

	r.POST("/api/keys/global", func(c *gin.Context) {
		file, err := c.FormFile("key")
		if err != nil {
			audit(c, "global_key.upload", "global_key", "global", "failure", "Missing key file", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing key file"})
			return
		}
		key, err := readUploadedPrivateKey(file)
		if err != nil {
			if errors.Is(err, errUploadedKeyTooLarge) {
				audit(c, "global_key.upload", "global_key", "global", "failure", "Uploaded key too large", nil)
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
				return
			}
			if errors.Is(err, errUploadedKeyEmpty) {
				audit(c, "global_key.upload", "global_key", "global", "failure", "Uploaded key empty", nil)
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			audit(c, "global_key.upload", "global_key", "global", "failure", "Failed to read key", nil)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read key"})
			return
		}
		if err := setGlobalKey(key); err != nil {
			audit(c, "global_key.upload", "global_key", "global", "failure", "Failed to save global key", map[string]any{"error": err.Error()})
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		audit(c, "global_key.upload", "global_key", "global", "success", "Global key saved", nil)
		c.JSON(http.StatusOK, gin.H{"message": "Global key saved"})
	})

	r.DELETE("/api/keys/global", func(c *gin.Context) {
		if err := clearGlobalKey(); err != nil {
			audit(c, "global_key.clear", "global_key", "global", "failure", "Failed to clear global key", map[string]any{"error": err.Error()})
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		audit(c, "global_key.clear", "global_key", "global", "success", "Global key cleared", nil)
		c.JSON(http.StatusOK, gin.H{"message": "Global key cleared"})
	})

	r.GET("/api/keys/global", func(c *gin.Context) {
		db := getDB()
		var enc string
		err := db.QueryRow("SELECT value FROM settings WHERE key = ?", globalKeySetting).Scan(&enc)
		if err == sql.ErrNoRows || strings.TrimSpace(enc) == "" {
			c.JSON(http.StatusOK, gin.H{"has_key": false})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read global key"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"has_key": true})
	})

	r.GET("/api/audit-events", func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
		if pageSize < 1 {
			pageSize = 50
		}
		if pageSize > 200 {
			pageSize = 200
		}
		targetName := strings.TrimSpace(c.Query("target_name"))
		action := strings.TrimSpace(c.Query("action"))
		status := strings.TrimSpace(c.Query("status"))
		from := strings.TrimSpace(c.Query("from"))
		to := strings.TrimSpace(c.Query("to"))
		offset := (page - 1) * pageSize

		var whereParts []string
		var args []any
		if targetName != "" {
			whereParts = append(whereParts, "target_name = ?")
			args = append(args, targetName)
		}
		if action != "" {
			whereParts = append(whereParts, "action = ?")
			args = append(args, action)
		}
		if status != "" {
			whereParts = append(whereParts, "status = ?")
			args = append(args, status)
		}
		if from != "" {
			normalizedFrom, err := normalizeAuditFilterTimestamp(from)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from timestamp; expected RFC3339"})
				return
			}
			whereParts = append(whereParts, "created_at >= ?")
			args = append(args, normalizedFrom)
		}
		if to != "" {
			normalizedTo, err := normalizeAuditFilterTimestamp(to)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to timestamp; expected RFC3339"})
				return
			}
			whereParts = append(whereParts, "created_at <= ?")
			args = append(args, normalizedTo)
		}

		whereClause := ""
		if len(whereParts) > 0 {
			whereClause = " WHERE " + strings.Join(whereParts, " AND ")
		}

		db := getDB()
		countQuery := "SELECT COUNT(*) FROM audit_events" + whereClause
		var total int
		if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count audit events"})
			return
		}

		query := `SELECT id, created_at, actor, action, target_type, target_name, status, message, meta_json, request_id, client_ip
			FROM audit_events` + whereClause + ` ORDER BY id DESC LIMIT ? OFFSET ?`
		queryArgs := append(append([]any{}, args...), pageSize, offset)
		rows, err := db.Query(query, queryArgs...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load audit events"})
			return
		}
		defer rows.Close()

		items := make([]AuditEvent, 0, pageSize)
		for rows.Next() {
			var evt AuditEvent
			if err := rows.Scan(
				&evt.ID,
				&evt.CreatedAt,
				&evt.Actor,
				&evt.Action,
				&evt.TargetType,
				&evt.TargetName,
				&evt.Status,
				&evt.Message,
				&evt.MetaJSON,
				&evt.RequestID,
				&evt.ClientIP,
			); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse audit events"})
				return
			}
			items = append(items, evt)
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to iterate audit events"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"items":     items,
			"page":      page,
			"page_size": pageSize,
			"total":     total,
		})
	})

	r.POST("/api/audit-events/prune", func(c *gin.Context) {
		if err := pruneAuditEvents(auditRetentionDays); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prune audit events"})
			return
		}
		audit(c, "audit.prune", "system", "audit_events", "success", fmt.Sprintf("Pruned entries older than %d days", auditRetentionDays), map[string]any{"retention_days": auditRetentionDays})
		c.JSON(http.StatusOK, gin.H{"message": "Audit events pruned"})
	})

	r.POST("/api/hostkeys/scan", func(c *gin.Context) {
		var req struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			audit(c, "hostkey.scan", "hostkey", "-", "failure", "Invalid request payload", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		host := strings.TrimSpace(req.Host)
		if host == "" {
			audit(c, "hostkey.scan", "hostkey", "-", "failure", "Host is required", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": "host is required"})
			return
		}
		port := normalizePort(req.Port)
		key, err := scanHostKeyFunc(host, port)
		if err != nil {
			audit(c, "hostkey.scan", "hostkey", host, "failure", "Host key scan failed", map[string]any{"port": port, "error": err.Error()})
			c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("failed to scan host key: %v", err)})
			return
		}
		audit(c, "hostkey.scan", "hostkey", host, "success", "Host key scanned", map[string]any{"port": port, "algorithm": key.Type()})
		c.JSON(http.StatusOK, gin.H{
			"host":               host,
			"port":               port,
			"algorithm":          key.Type(),
			"fingerprint_sha256": ssh.FingerprintSHA256(key),
			"known_hosts_line":   buildKnownHostsLine(host, port, key),
		})
	})

	r.POST("/api/hostkeys/trust", func(c *gin.Context) {
		var req struct {
			Host              string `json:"host"`
			Port              int    `json:"port"`
			FingerprintSHA256 string `json:"fingerprint_sha256"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			audit(c, "hostkey.trust", "hostkey", "-", "failure", "Invalid request payload", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		host := strings.TrimSpace(req.Host)
		if host == "" {
			audit(c, "hostkey.trust", "hostkey", "-", "failure", "Host is required", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": "host is required"})
			return
		}
		expectedFingerprint := strings.TrimSpace(req.FingerprintSHA256)
		if expectedFingerprint == "" {
			audit(c, "hostkey.trust", "hostkey", host, "failure", "Fingerprint is required", nil)
			c.JSON(http.StatusBadRequest, gin.H{"error": "fingerprint_sha256 is required"})
			return
		}
		port := normalizePort(req.Port)
		fingerprint, line, err := trustHostKey(host, port, expectedFingerprint)
		if err != nil {
			if errors.Is(err, errFingerprintMismatch) {
				audit(c, "hostkey.trust", "hostkey", host, "failure", "Host key fingerprint mismatch", map[string]any{"port": port})
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			audit(c, "hostkey.trust", "hostkey", host, "failure", "Failed to trust host key", map[string]any{"port": port, "error": err.Error()})
			c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("failed to trust host key: %v", err)})
			return
		}
		audit(c, "hostkey.trust", "hostkey", host, "success", "Host key trusted", map[string]any{"port": port, "fingerprint_sha256": fingerprint})
		c.JSON(http.StatusOK, gin.H{
			"message":            "Host key trusted",
			"host":               host,
			"port":               port,
			"fingerprint_sha256": fingerprint,
			"known_hosts_line":   line,
		})
	})

	r.POST("/api/update/:name", func(c *gin.Context) {
		name := c.Param("name")
		actor := actorFromContext(c)
		ip := clientIPFromContext(c)
		retryPolicy := loadRetryPolicyFromEnv()
		retryMeta := map[string]any{
			"max_attempts":        retryPolicy.MaxAttempts,
			"base_delay_ms":       int(retryPolicy.BaseDelay / time.Millisecond),
			"max_delay_ms":        int(retryPolicy.MaxDelay / time.Millisecond),
			"jitter_pct":          retryPolicy.JitterPct,
			"total_attempts_used": 0,
			"retry_exhausted":     false,
		}
		server, err := beginServerAction(name, "updating")
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				audit(c, "update.start", "server", name, "failure", "Server not found", retryMeta)
				c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
				return
			}
			if errors.Is(err, errActionInProgress) {
				audit(c, "update.start", "server", name, "failure", "Action already in progress", retryMeta)
				c.JSON(http.StatusConflict, gin.H{"error": "Update already in progress"})
				return
			}
			retryMeta["error"] = err.Error()
			audit(c, "update.start", "server", name, "failure", "Failed to start update", retryMeta)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start update"})
			return
		}
		go runUpdateWithActor(server, actor, ip, retryPolicy)
		audit(c, "update.start", "server", name, "started", "Update started", retryMeta)
		c.JSON(http.StatusOK, gin.H{"message": "Update started"})
	})

	r.POST("/api/autoremove/:name", func(c *gin.Context) {
		name := c.Param("name")
		actor := actorFromContext(c)
		ip := clientIPFromContext(c)
		retryPolicy := loadRetryPolicyFromEnv()
		retryMeta := map[string]any{
			"max_attempts":        retryPolicy.MaxAttempts,
			"base_delay_ms":       int(retryPolicy.BaseDelay / time.Millisecond),
			"max_delay_ms":        int(retryPolicy.MaxDelay / time.Millisecond),
			"jitter_pct":          retryPolicy.JitterPct,
			"total_attempts_used": 0,
			"retry_exhausted":     false,
		}
		server, err := beginServerAction(name, "autoremove")
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				audit(c, "autoremove.start", "server", name, "failure", "Server not found", retryMeta)
				c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
				return
			}
			if errors.Is(err, errActionInProgress) {
				audit(c, "autoremove.start", "server", name, "failure", "Action already in progress", retryMeta)
				c.JSON(http.StatusConflict, gin.H{"error": "Update already in progress"})
				return
			}
			retryMeta["error"] = err.Error()
			audit(c, "autoremove.start", "server", name, "failure", "Failed to start autoremove", retryMeta)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start autoremove"})
			return
		}
		go runAutoremoveWithActor(server, actor, ip, retryPolicy)
		audit(c, "autoremove.start", "server", name, "started", "Autoremove started", retryMeta)
		c.JSON(http.StatusOK, gin.H{"message": "Autoremove started"})
	})

	r.POST("/api/sudoers/:name", func(c *gin.Context) {
		name := c.Param("name")
		actor := actorFromContext(c)
		ip := clientIPFromContext(c)
		retryPolicy := loadRetryPolicyFromEnv()
		retryMeta := map[string]any{
			"max_attempts":        retryPolicy.MaxAttempts,
			"base_delay_ms":       int(retryPolicy.BaseDelay / time.Millisecond),
			"max_delay_ms":        int(retryPolicy.MaxDelay / time.Millisecond),
			"jitter_pct":          retryPolicy.JitterPct,
			"total_attempts_used": 0,
			"retry_exhausted":     false,
		}
		var req struct {
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			audit(c, "sudoers.enable.start", "server", name, "failure", "Invalid request payload", retryMeta)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if strings.TrimSpace(req.Password) == "" {
			audit(c, "sudoers.enable.start", "server", name, "failure", "Missing sudo password", retryMeta)
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing sudo password"})
			return
		}
		server, err := beginServerAction(name, "sudoers")
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				audit(c, "sudoers.enable.start", "server", name, "failure", "Server not found", retryMeta)
				c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
				return
			}
			if errors.Is(err, errActionInProgress) {
				audit(c, "sudoers.enable.start", "server", name, "failure", "Action already in progress", retryMeta)
				c.JSON(http.StatusConflict, gin.H{"error": "Update already in progress"})
				return
			}
			retryMeta["error"] = err.Error()
			audit(c, "sudoers.enable.start", "server", name, "failure", "Failed to start sudoers setup", retryMeta)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start sudoers setup"})
			return
		}
		go runSudoersBootstrapWithActor(server, req.Password, actor, ip, retryPolicy)
		audit(c, "sudoers.enable.start", "server", name, "started", "Sudoers setup started", retryMeta)
		c.JSON(http.StatusOK, gin.H{"message": "Sudoers setup started"})
	})

	r.POST("/api/sudoers/disable/:name", func(c *gin.Context) {
		name := c.Param("name")
		actor := actorFromContext(c)
		ip := clientIPFromContext(c)
		retryPolicy := loadRetryPolicyFromEnv()
		retryMeta := map[string]any{
			"max_attempts":        retryPolicy.MaxAttempts,
			"base_delay_ms":       int(retryPolicy.BaseDelay / time.Millisecond),
			"max_delay_ms":        int(retryPolicy.MaxDelay / time.Millisecond),
			"jitter_pct":          retryPolicy.JitterPct,
			"total_attempts_used": 0,
			"retry_exhausted":     false,
		}
		var req struct {
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			audit(c, "sudoers.disable.start", "server", name, "failure", "Invalid request payload", retryMeta)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if strings.TrimSpace(req.Password) == "" {
			audit(c, "sudoers.disable.start", "server", name, "failure", "Missing sudo password", retryMeta)
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing sudo password"})
			return
		}
		server, err := beginServerAction(name, "sudoers")
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				audit(c, "sudoers.disable.start", "server", name, "failure", "Server not found", retryMeta)
				c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
				return
			}
			if errors.Is(err, errActionInProgress) {
				audit(c, "sudoers.disable.start", "server", name, "failure", "Action already in progress", retryMeta)
				c.JSON(http.StatusConflict, gin.H{"error": "Update already in progress"})
				return
			}
			retryMeta["error"] = err.Error()
			audit(c, "sudoers.disable.start", "server", name, "failure", "Failed to start sudoers disable", retryMeta)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start sudoers disable"})
			return
		}
		go runSudoersDisableWithActor(server, req.Password, actor, ip, retryPolicy)
		audit(c, "sudoers.disable.start", "server", name, "started", "Sudoers disable started", retryMeta)
		c.JSON(http.StatusOK, gin.H{"message": "Sudoers disable started"})
	})

	r.POST("/api/approve/:name", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		status, exists := statusMap[name]
		approved := false
		if exists && status.Status == "pending_approval" {
			status.Status = "approved"
			approved = true
		}
		mu.Unlock()
		if !exists {
			audit(c, "update.approve", "server", name, "failure", "Server not found", nil)
			c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
			return
		}
		if approved {
			audit(c, "update.approve", "server", name, "success", "Upgrade approved", nil)
		} else {
			audit(c, "update.approve", "server", name, "ignored", "Server not pending approval", nil)
		}
		c.JSON(http.StatusOK, gin.H{"message": "Upgrade approved"})
	})

	r.POST("/api/cancel/:name", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		status, exists := statusMap[name]
		cancelled := false
		if exists && status.Status == "pending_approval" {
			status.Status = "cancelled"
			status.Logs = ""
			status.Upgradable = nil
			cancelled = true
		}
		mu.Unlock()
		if !exists {
			audit(c, "update.cancel", "server", name, "failure", "Server not found", nil)
			c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
			return
		}
		if cancelled {
			audit(c, "update.cancel", "server", name, "success", "Upgrade cancelled", nil)
		} else {
			audit(c, "update.cancel", "server", name, "ignored", "Server not pending approval", nil)
		}
		c.JSON(http.StatusOK, gin.H{"message": "Upgrade cancelled"})
	})

	r.GET("/api/logs/:name", func(c *gin.Context) {
		name := c.Param("name")
		mu.Lock()
		status, exists := statusMap[name]
		if !exists || status == nil {
			mu.Unlock()
			c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
			return
		}
		logs := status.Logs
		mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"logs": logs})
	})

	log.Println("Starting web server on :8080")
	r.Run(":8080")
}
