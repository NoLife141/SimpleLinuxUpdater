package main

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
)

func preserveServerState(t *testing.T) {
	t.Helper()
	mu.Lock()
	origServers := cloneServers(servers)
	origStatusMap := cloneStatusMap(statusMap)
	origSaveServersFunc := saveServersFunc
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		servers = origServers
		statusMap = origStatusMap
		saveServersFunc = origSaveServersFunc
		mu.Unlock()
	})
}

func preserveDBState(t *testing.T) {
	t.Helper()
	origDB := db
	origOncePtr := &dbOnce
	origOnceDone := origDB != nil
	db = nil
	*origOncePtr = sync.Once{}
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
		db = origDB
		*origOncePtr = sync.Once{}
		if origOnceDone {
			origOncePtr.Do(func() {})
		}
	})
}

func TestBasicAuthFromEnv(t *testing.T) {
	t.Setenv(basicAuthUserEnv, "")
	t.Setenv(basicAuthPassEnv, "")
	_, _, enabled, err := basicAuthFromEnv()
	if err != nil {
		t.Fatalf("basicAuthFromEnv() unexpected error: %v", err)
	}
	if enabled {
		t.Fatalf("basicAuthFromEnv() enabled = true, want false")
	}

	t.Setenv(basicAuthUserEnv, "admin")
	t.Setenv(basicAuthPassEnv, "")
	_, _, _, err = basicAuthFromEnv()
	if err == nil {
		t.Fatalf("basicAuthFromEnv() expected error when only one credential is set")
	}

	t.Setenv(basicAuthUserEnv, "admin")
	t.Setenv(basicAuthPassEnv, "secret")
	user, pass, enabled, err := basicAuthFromEnv()
	if err != nil {
		t.Fatalf("basicAuthFromEnv() unexpected error: %v", err)
	}
	if !enabled {
		t.Fatalf("basicAuthFromEnv() enabled = false, want true")
	}
	if user != "admin" || pass != "secret" {
		t.Fatalf("basicAuthFromEnv() = (%q, %q), want (%q, %q)", user, pass, "admin", "secret")
	}
}

func TestBasicAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(basicAuthMiddleware("admin", "secret"))
	r.GET("/ok", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.SetBasicAuth("admin", "wrong")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad auth status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.SetBasicAuth("admin", "secret")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid auth status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestStringsEqualConstantTime(t *testing.T) {
	if !stringsEqualConstantTime("same-value", "same-value") {
		t.Fatalf("stringsEqualConstantTime() = false, want true for equal values")
	}
	if stringsEqualConstantTime("same-value", "different-value") {
		t.Fatalf("stringsEqualConstantTime() = true, want false for different values")
	}
	if stringsEqualConstantTime("short", "longer") {
		t.Fatalf("stringsEqualConstantTime() = true, want false for different lengths")
	}
}

func TestNormalizeAuditFilterTimestamp(t *testing.T) {
	got, err := normalizeAuditFilterTimestamp("2026-02-10T12:00:00+02:00")
	if err != nil {
		t.Fatalf("normalizeAuditFilterTimestamp(valid) unexpected error: %v", err)
	}
	want := "2026-02-10T10:00:00Z"
	if got != want {
		t.Fatalf("normalizeAuditFilterTimestamp() = %q, want %q", got, want)
	}
	if _, err := normalizeAuditFilterTimestamp("not-a-timestamp"); err == nil {
		t.Fatalf("normalizeAuditFilterTimestamp(invalid) error = nil, want non-nil")
	}
}

func TestUpdateCompletionOutcome(t *testing.T) {
	if got := updateCompletionOutcome("done"); got != "success" {
		t.Fatalf("updateCompletionOutcome(done) = %q, want success", got)
	}
	if got := updateCompletionOutcome("idle"); got != "ignored" {
		t.Fatalf("updateCompletionOutcome(idle) = %q, want ignored", got)
	}
	if got := updateCompletionOutcome("error"); got != "failure" {
		t.Fatalf("updateCompletionOutcome(error) = %q, want failure", got)
	}
}

func TestServerNameAndHostExistsLocked(t *testing.T) {
	preserveServerState(t)

	mu.Lock()
	defer mu.Unlock()
	servers = []Server{
		{Name: "Alpha", Host: "node-a.example"},
		{Name: "Beta", Host: "NODE-B.EXAMPLE"},
	}

	if !serverNameExistsLocked("alpha", -1) {
		t.Fatalf("serverNameExistsLocked(alpha) = false, want true")
	}
	if serverNameExistsLocked("alpha", 0) {
		t.Fatalf("serverNameExistsLocked(alpha, skip=0) = true, want false")
	}
	if serverNameExistsLocked("gamma", -1) {
		t.Fatalf("serverNameExistsLocked(gamma) = true, want false")
	}

	if !serverHostExistsLocked("node-b.example", -1) {
		t.Fatalf("serverHostExistsLocked(node-b.example) = false, want true")
	}
	if serverHostExistsLocked("node-b.example", 1) {
		t.Fatalf("serverHostExistsLocked(node-b.example, skip=1) = true, want false")
	}
	if serverHostExistsLocked("node-c.example", -1) {
		t.Fatalf("serverHostExistsLocked(node-c.example) = true, want false")
	}
}

func TestReadUploadedKeyDataLimit(t *testing.T) {
	key := bytes.Repeat([]byte("a"), maxUploadedKeyBytes)
	got, err := readUploadedKeyData(bytes.NewReader(key))
	if err != nil {
		t.Fatalf("readUploadedKeyData(valid) unexpected error: %v", err)
	}
	if len(got) != maxUploadedKeyBytes {
		t.Fatalf("readUploadedKeyData(valid) len = %d, want %d", len(got), maxUploadedKeyBytes)
	}

	_, err = readUploadedKeyData(bytes.NewReader(bytes.Repeat([]byte("a"), maxUploadedKeyBytes+1)))
	if !errors.Is(err, errUploadedKeyTooLarge) {
		t.Fatalf("readUploadedKeyData(too large) err = %v, want %v", err, errUploadedKeyTooLarge)
	}

	_, err = readUploadedKeyData(bytes.NewReader([]byte("   \n\t  ")))
	if !errors.Is(err, errUploadedKeyEmpty) {
		t.Fatalf("readUploadedKeyData(empty) err = %v, want %v", err, errUploadedKeyEmpty)
	}
}

func TestBeginServerAction(t *testing.T) {
	preserveServerState(t)

	mu.Lock()
	servers = []Server{
		{Name: "srv-a", Host: "a.example", Port: 22, User: "user"},
	}
	statusMap = map[string]*ServerStatus{
		"srv-a": {Name: "srv-a", Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	server, err := beginServerAction("srv-a", "updating")
	if err != nil {
		t.Fatalf("beginServerAction() unexpected error: %v", err)
	}
	if server.Name != "srv-a" {
		t.Fatalf("beginServerAction() server name = %q, want %q", server.Name, "srv-a")
	}

	mu.Lock()
	currentStatus := statusMap["srv-a"].Status
	mu.Unlock()
	if currentStatus != "updating" {
		t.Fatalf("beginServerAction() status = %q, want %q", currentStatus, "updating")
	}

	_, err = beginServerAction("srv-a", "autoremove")
	if !errors.Is(err, errActionInProgress) {
		t.Fatalf("beginServerAction() second call err = %v, want %v", err, errActionInProgress)
	}

	_, err = beginServerAction("missing", "updating")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("beginServerAction(missing) err = %v, want %v", err, sql.ErrNoRows)
	}
}

func TestWorkersDoNotPanicWhenStatusMissing(t *testing.T) {
	preserveServerState(t)

	mu.Lock()
	servers = nil
	statusMap = map[string]*ServerStatus{}
	mu.Unlock()

	assertNoPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s panicked: %v", name, r)
			}
		}()
		fn()
	}

	server := Server{Name: "missing"}
	assertNoPanic("runUpdate", func() { runUpdate(server) })
	assertNoPanic("runAutoremove", func() { runAutoremove(server) })
	assertNoPanic("runSudoersBootstrap", func() { runSudoersBootstrap(server, "pw") })
	assertNoPanic("runSudoersDisable", func() { runSudoersDisable(server, "pw") })
}

func TestTrustHostKeyWritesKnownHosts(t *testing.T) {
	tmpDir := t.TempDir()
	knownHosts := filepath.Join(tmpDir, "known_hosts")
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHosts)

	_, privateKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}

	origScanner := scanHostKeyFunc
	scanHostKeyFunc = func(_ string, _ int) (ssh.PublicKey, error) {
		return signer.PublicKey(), nil
	}
	t.Cleanup(func() {
		scanHostKeyFunc = origScanner
	})

	expectedFingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	gotFingerprint, line, err := trustHostKey("example.com", 2222, expectedFingerprint)
	if err != nil {
		t.Fatalf("trustHostKey() unexpected error: %v", err)
	}
	if gotFingerprint != expectedFingerprint {
		t.Fatalf("trustHostKey() fingerprint = %q, want %q", gotFingerprint, expectedFingerprint)
	}
	if line == "" {
		t.Fatalf("trustHostKey() line is empty")
	}

	raw, err := os.ReadFile(knownHosts)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, line) {
		t.Fatalf("known_hosts missing trusted line")
	}

	_, _, err = trustHostKey("example.com", 2222, expectedFingerprint)
	if err != nil {
		t.Fatalf("trustHostKey() duplicate unexpected error: %v", err)
	}
	raw, err = os.ReadFile(knownHosts)
	if err != nil {
		t.Fatalf("ReadFile() after duplicate error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("known_hosts lines = %d, want 1", len(lines))
	}
}

func TestTrustHostKeyFingerprintMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	knownHosts := filepath.Join(tmpDir, "known_hosts")
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHosts)

	_, privateKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}

	origScanner := scanHostKeyFunc
	scanHostKeyFunc = func(_ string, _ int) (ssh.PublicKey, error) {
		return signer.PublicKey(), nil
	}
	t.Cleanup(func() {
		scanHostKeyFunc = origScanner
	})

	_, _, err = trustHostKey("example.com", 22, "SHA256:not-the-real-fingerprint")
	if !errors.Is(err, errFingerprintMismatch) {
		t.Fatalf("trustHostKey() err = %v, want %v", err, errFingerprintMismatch)
	}
}

func TestKnownHostsPathsDefaultUsesDataDir(t *testing.T) {
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", "")
	tmpDir := t.TempDir()
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(tmpDir, "servers.db"))

	paths := knownHostsPaths()
	if len(paths) == 0 {
		t.Fatalf("knownHostsPaths() returned no paths")
	}
	wantFirst := filepath.Join(tmpDir, "known_hosts")
	if paths[0] != wantFirst {
		t.Fatalf("knownHostsPaths()[0] = %q, want %q", paths[0], wantFirst)
	}
}

func TestSaveServersOrRollbackLockedOnFailure(t *testing.T) {
	preserveServerState(t)

	mu.Lock()
	servers = []Server{
		{Name: "srv-a", Host: "a.example", Port: 22, User: "user-a"},
	}
	statusMap = map[string]*ServerStatus{
		"srv-a": {Name: "srv-a", Status: "idle", Upgradable: []string{}},
	}
	prevServers := cloneServers(servers)
	prevStatusMap := cloneStatusMap(statusMap)

	servers = append(servers, Server{Name: "srv-b", Host: "b.example", Port: 22, User: "user-b"})
	statusMap["srv-b"] = &ServerStatus{Name: "srv-b", Status: "idle", Upgradable: []string{}}

	saveServersFunc = func() error {
		return errors.New("forced save failure")
	}
	err := saveServersOrRollbackLocked(prevServers, prevStatusMap)
	if err == nil {
		mu.Unlock()
		t.Fatalf("saveServersOrRollbackLocked() error = nil, want non-nil")
	}
	if !reflect.DeepEqual(servers, prevServers) {
		mu.Unlock()
		t.Fatalf("servers were not rolled back on save failure")
	}
	if !reflect.DeepEqual(statusMap, prevStatusMap) {
		mu.Unlock()
		t.Fatalf("statusMap was not rolled back on save failure")
	}
	mu.Unlock()
}

func TestEnsureSchemaCreatesAuditArtifacts(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "schema.db")
	testDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer testDB.Close()
	if _, err := testDB.Exec(`
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
	`); err != nil {
		t.Fatalf("create servers table error = %v", err)
	}

	if err := ensureSchema(testDB); err != nil {
		t.Fatalf("ensureSchema() error = %v", err)
	}

	var count int
	if err := testDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_events'").Scan(&count); err != nil {
		t.Fatalf("table query error = %v", err)
	}
	if count != 1 {
		t.Fatalf("audit_events table missing")
	}
	for _, idx := range []string{"idx_audit_created_at", "idx_audit_target", "idx_audit_action"} {
		if err := testDB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&count); err != nil {
			t.Fatalf("index query error = %v", err)
		}
		if count != 1 {
			t.Fatalf("index %s missing", idx)
		}
	}
}

func TestActorFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := actorFromContext(c); got != "unknown" {
		t.Fatalf("actorFromContext() = %q, want unknown", got)
	}
	c.Set("actor", "admin")
	if got := actorFromContext(c); got != "admin" {
		t.Fatalf("actorFromContext() = %q, want admin", got)
	}
}

func TestSanitizeAuditMetaRedactsSecrets(t *testing.T) {
	meta := map[string]any{
		"host":      "srv-1",
		"password":  "secret",
		"ssh_key":   "private",
		"error":     "boom",
		"api_token": "token-value",
	}
	raw := sanitizeAuditMeta(meta)
	if strings.Contains(raw, "secret") || strings.Contains(raw, "private") || strings.Contains(raw, "token-value") {
		t.Fatalf("sanitizeAuditMeta() leaked secret data: %s", raw)
	}
	if !strings.Contains(raw, "srv-1") || !strings.Contains(raw, "boom") {
		t.Fatalf("sanitizeAuditMeta() dropped expected safe values: %s", raw)
	}
}

func TestSanitizeAuditMetaDoesNotOverRedactPassSubstrings(t *testing.T) {
	meta := map[string]any{
		"compass": "north",
		"bypass":  true,
		"pass":    "secret",
	}
	raw := sanitizeAuditMeta(meta)
	if strings.Contains(raw, "secret") {
		t.Fatalf("sanitizeAuditMeta() leaked pass value: %s", raw)
	}
	if !strings.Contains(raw, "compass") || !strings.Contains(raw, "bypass") {
		t.Fatalf("sanitizeAuditMeta() over-redacted benign pass substrings: %s", raw)
	}
}

func TestSanitizeAuditMetaAddsTruncationMarker(t *testing.T) {
	huge := strings.Repeat("x", auditMetaMaxLen*2)
	raw := sanitizeAuditMeta(map[string]any{
		"host": "srv-1",
		"blob": huge,
	})
	if len(raw) > auditMetaMaxLen {
		t.Fatalf("sanitizeAuditMeta() len = %d, want <= %d", len(raw), auditMetaMaxLen)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("sanitizeAuditMeta() returned invalid JSON: %v", err)
	}
	flag, ok := decoded["_truncated"].(bool)
	if !ok || !flag {
		t.Fatalf("sanitizeAuditMeta() missing _truncated marker: %s", raw)
	}
	if _, ok := decoded["original_length"]; !ok {
		t.Fatalf("sanitizeAuditMeta() missing original_length: %s", raw)
	}
}

func TestWriteAuditEventAndPrune(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "audit.db"))
	_ = getDB()

	newEvt := AuditEvent{
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Actor:      "admin",
		Action:     "server.create",
		TargetType: "server",
		TargetName: "srv-new",
		Status:     "success",
		Message:    "created",
		MetaJSON:   `{"host":"srv-new"}`,
	}
	if err := writeAuditEvent(newEvt); err != nil {
		t.Fatalf("writeAuditEvent(new) error = %v", err)
	}

	oldDate := time.Now().UTC().AddDate(0, 0, -(auditRetentionDays + 2)).Format(time.RFC3339)
	oldEvt := AuditEvent{
		CreatedAt:  oldDate,
		Actor:      "admin",
		Action:     "server.delete",
		TargetType: "server",
		TargetName: "srv-old",
		Status:     "success",
		Message:    "deleted",
		MetaJSON:   "{}",
	}
	if err := writeAuditEvent(oldEvt); err != nil {
		t.Fatalf("writeAuditEvent(old) error = %v", err)
	}

	if err := pruneAuditEvents(auditRetentionDays); err != nil {
		t.Fatalf("pruneAuditEvents() error = %v", err)
	}

	rows, err := getDB().Query("SELECT target_name FROM audit_events ORDER BY id")
	if err != nil {
		t.Fatalf("query audit_events error = %v", err)
	}
	defer rows.Close()
	var targets []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			t.Fatalf("scan error = %v", err)
		}
		targets = append(targets, target)
	}
	if len(targets) != 1 || targets[0] != "srv-new" {
		t.Fatalf("unexpected audit rows after prune: %v", targets)
	}
}

func TestAuditEventsAPIFiltering(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "audit_api.db"))
	_ = getDB()

	base := time.Date(2026, 2, 10, 10, 0, 0, 0, time.UTC)
	seed := []AuditEvent{
		{CreatedAt: base.Add(-3 * time.Hour).Format(time.RFC3339), Actor: "admin", Action: "server.create", TargetType: "server", TargetName: "alpha", Status: "success", Message: "alpha-ok", MetaJSON: "{}"},
		{CreatedAt: base.Add(-2 * time.Hour).Format(time.RFC3339), Actor: "admin", Action: "server.update", TargetType: "server", TargetName: "beta", Status: "failure", Message: "beta-fail-1", MetaJSON: "{}"},
		{CreatedAt: base.Add(-1 * time.Hour).Format(time.RFC3339), Actor: "admin", Action: "server.update", TargetType: "server", TargetName: "beta", Status: "failure", Message: "beta-fail-2", MetaJSON: "{}"},
		{CreatedAt: base.Add(-30 * time.Minute).Format(time.RFC3339), Actor: "admin", Action: "server.update", TargetType: "server", TargetName: "beta", Status: "success", Message: "beta-ok", MetaJSON: "{}"},
	}
	for _, evt := range seed {
		if err := writeAuditEvent(evt); err != nil {
			t.Fatalf("seed writeAuditEvent() error = %v", err)
		}
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/audit-events", handleAuditEvents)

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/audit-events?target_name=beta&action=server.update&status=failure&from=2026-02-10T07:30:00Z&to=2026-02-10T09:30:00Z&page=1&page_size=1",
		nil,
	)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload struct {
		Items    []AuditEvent `json:"items"`
		Page     int          `json:"page"`
		PageSize int          `json:"page_size"`
		Total    int          `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json unmarshal error = %v", err)
	}
	if payload.Total != 2 {
		t.Fatalf("filtered total = %d, want 2", payload.Total)
	}
	if payload.Page != 1 || payload.PageSize != 1 {
		t.Fatalf("unexpected pagination: page=%d page_size=%d", payload.Page, payload.PageSize)
	}
	if len(payload.Items) != 1 || payload.Items[0].Message != "beta-fail-2" {
		t.Fatalf("unexpected first page items: %+v", payload.Items)
	}

	req = httptest.NewRequest(
		http.MethodGet,
		"/api/audit-events?target_name=beta&action=server.update&status=failure&from=2026-02-10T07:30:00Z&to=2026-02-10T09:30:00Z&page=2&page_size=1",
		nil,
	)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second page status = %d, want %d", rec.Code, http.StatusOK)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("second page json unmarshal error = %v", err)
	}
	if payload.Total != 2 || len(payload.Items) != 1 || payload.Items[0].Message != "beta-fail-1" {
		t.Fatalf("unexpected second page payload: %+v", payload)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/audit-events?from=invalid", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid from status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
