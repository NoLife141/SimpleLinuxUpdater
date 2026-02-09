package main

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
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

func TestServerNameAndHostExistsLocked(t *testing.T) {
	preserveServerState(t)

	mu.Lock()
	servers = []Server{
		{Name: "Alpha", Host: "node-a.example"},
		{Name: "Beta", Host: "NODE-B.EXAMPLE"},
	}

	if !serverNameExistsLocked("alpha", -1) {
		mu.Unlock()
		t.Fatalf("serverNameExistsLocked(alpha) = false, want true")
	}
	if serverNameExistsLocked("alpha", 0) {
		mu.Unlock()
		t.Fatalf("serverNameExistsLocked(alpha, skip=0) = true, want false")
	}
	if serverNameExistsLocked("gamma", -1) {
		mu.Unlock()
		t.Fatalf("serverNameExistsLocked(gamma) = true, want false")
	}

	if !serverHostExistsLocked("node-b.example", -1) {
		mu.Unlock()
		t.Fatalf("serverHostExistsLocked(node-b.example) = false, want true")
	}
	if serverHostExistsLocked("node-b.example", 1) {
		mu.Unlock()
		t.Fatalf("serverHostExistsLocked(node-b.example, skip=1) = true, want false")
	}
	if serverHostExistsLocked("node-c.example", -1) {
		mu.Unlock()
		t.Fatalf("serverHostExistsLocked(node-c.example) = true, want false")
	}
	mu.Unlock()
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
