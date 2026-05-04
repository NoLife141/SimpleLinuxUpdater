package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

func preserveEncryptionState(t *testing.T) {
	t.Helper()
	origKey := encryptionKey
	encryptionKey = nil
	keyOnce = sync.Once{}
	t.Cleanup(func() {
		encryptionKey = origKey
		keyOnce = sync.Once{}
		if origKey != nil {
			keyOnce.Do(func() {})
		}
	})
}

func TestGetEncryptionKeyConcurrentInitializationUsesPersistedKey(t *testing.T) {
	preserveEncryptionState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "encryption-race.db"))

	const callers = 16
	results := make(chan []byte, callers)
	for range callers {
		go func() {
			results <- append([]byte(nil), getEncryptionKey()...)
		}()
	}

	var first []byte
	for i := 0; i < callers; i++ {
		got := <-results
		if len(got) != 32 {
			t.Fatalf("getEncryptionKey() len = %d, want 32", len(got))
		}
		if i == 0 {
			first = got
			continue
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("concurrent getEncryptionKey() returned different keys")
		}
	}

	raw, err := os.ReadFile(configPath())
	if err != nil {
		t.Fatalf("ReadFile(configPath()) unexpected error: %v", err)
	}
	var cfg map[string]string
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config unmarshal unexpected error: %v", err)
	}
	persisted, err := base64.StdEncoding.DecodeString(cfg["encryption_key"])
	if err != nil {
		t.Fatalf("persisted key decode unexpected error: %v", err)
	}
	if !bytes.Equal(persisted, first) {
		t.Fatalf("persisted encryption key differs from in-memory key")
	}
}

func TestRuntimeDataFilesAreOwnerOnly(t *testing.T) {
	preserveDBState(t)
	preserveEncryptionState(t)
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(runtimeDir, "servers.db"))

	_ = getEncryptionKey()
	_ = getDB()

	for _, tc := range []struct {
		path string
		mode os.FileMode
	}{
		{path: runtimeDir, mode: 0700},
		{path: configPath(), mode: 0600},
		{path: dbPath(), mode: 0600},
	} {
		info, err := os.Stat(tc.path)
		if err != nil {
			t.Fatalf("stat %s: %v", tc.path, err)
		}
		if got := info.Mode().Perm(); got != tc.mode {
			t.Fatalf("%s mode = %o, want %o", tc.path, got, tc.mode)
		}
	}
}

func TestLoadServersLeavesEmptyInventoryEmpty(t *testing.T) {
	preserveDBState(t)
	preserveEncryptionState(t)
	preserveServerState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "empty-inventory.db"))

	loadServers()

	mu.Lock()
	defer mu.Unlock()
	if len(servers) != 0 {
		t.Fatalf("loadServers seeded default servers: %+v", servers)
	}
}

func TestPersistActiveMaintenanceStateForRestoreWritesCurrentDatabase(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "restore-maintenance-marker.db"))

	state := MaintenanceState{
		Active:    true,
		Kind:      jobKindBackupRestore,
		JobID:     "restore-job",
		StartedAt: "2026-05-04T12:00:00Z",
		Actor:     "admin",
		Message:   "Restore in progress",
	}
	setCurrentMaintenanceState(state)
	t.Cleanup(func() {
		setCurrentMaintenanceState(MaintenanceState{})
	})

	if err := persistActiveMaintenanceStateForRestore(); err != nil {
		t.Fatalf("persistActiveMaintenanceStateForRestore() unexpected error: %v", err)
	}
	got, err := loadPersistedMaintenanceState()
	if err != nil {
		t.Fatalf("loadPersistedMaintenanceState() unexpected error: %v", err)
	}
	if !got.Active || got.JobID != state.JobID || got.Kind != state.Kind {
		t.Fatalf("persisted maintenance state = %+v, want active job=%q kind=%q", got, state.JobID, state.Kind)
	}
}

func TestBackupPayloadRoundTrip(t *testing.T) {
	files := map[string][]byte{
		"servers.db":  []byte("sqlite-snapshot"),
		"config.json": []byte(`{"encryption_key":"abc"}`),
		"known_hosts": []byte("host ssh-ed25519 AAAATEST"),
	}

	tarGz, err := buildBackupTarGz(map[string][]byte{
		"servers.db":  append([]byte(nil), files["servers.db"]...),
		"config.json": append([]byte(nil), files["config.json"]...),
		"known_hosts": append([]byte(nil), files["known_hosts"]...),
	})
	if err != nil {
		t.Fatalf("buildBackupTarGz() unexpected error: %v", err)
	}

	encrypted, err := encryptBackupPayload(tarGz, "very-strong-passphrase")
	if err != nil {
		t.Fatalf("encryptBackupPayload() unexpected error: %v", err)
	}

	plain, err := decryptBackupPayload(encrypted, "very-strong-passphrase")
	if err != nil {
		t.Fatalf("decryptBackupPayload(valid) unexpected error: %v", err)
	}
	if !bytes.Equal(plain, tarGz) {
		t.Fatalf("decryptBackupPayload(valid) payload mismatch")
	}

	restoredFiles, manifest, err := extractBackupTarGz(plain)
	if err != nil {
		t.Fatalf("extractBackupTarGz() unexpected error: %v", err)
	}
	for name, want := range files {
		got, ok := restoredFiles[name]
		if !ok {
			t.Fatalf("extractBackupTarGz() missing file %q", name)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("extractBackupTarGz() file %q mismatch", name)
		}
	}
	if manifest.Format != backupFormatName {
		t.Fatalf("manifest.Format = %q, want %q", manifest.Format, backupFormatName)
	}

	if _, err := decryptBackupPayload(encrypted, "wrong-passphrase"); err == nil {
		t.Fatalf("decryptBackupPayload(wrong passphrase) error = nil, want non-nil")
	}
}

func TestExtractBackupTarGzRejectsOversizedDecompressedPayload(t *testing.T) {
	tarGz, err := buildBackupTarGz(map[string][]byte{
		"servers.db":  []byte("sqlite-snapshot"),
		"config.json": []byte(`{"encryption_key":"abc"}`),
		"known_hosts": []byte("host ssh-ed25519 AAAATEST"),
	})
	if err != nil {
		t.Fatalf("buildBackupTarGz() unexpected error: %v", err)
	}

	_, _, err = extractBackupTarGzWithLimits(tarGz, 1024, 1)
	if err == nil {
		t.Fatalf("extractBackupTarGzWithLimits() error = nil, want decompressed size error")
	}
	if !strings.Contains(err.Error(), "backup payload is too large") {
		t.Fatalf("extractBackupTarGzWithLimits() error = %v, want payload size error", err)
	}
}

func TestExtractBackupTarGzCountsUnknownRegularEntries(t *testing.T) {
	manifest := backupManifest{
		Format:  backupFormatName,
		Version: backupFormatVersion,
		Files:   map[string]backupManifestFile{},
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal(manifest) unexpected error: %v", err)
	}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{name: "ignored.bin", data: bytes.Repeat([]byte("x"), 32)},
		{name: "manifest.json", data: manifestData},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.data))}); err != nil {
			t.Fatalf("WriteHeader(%q) unexpected error: %v", entry.name, err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			t.Fatalf("Write(%q) unexpected error: %v", entry.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close() unexpected error: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip.Close() unexpected error: %v", err)
	}

	_, _, err = extractBackupTarGzWithLimits(raw.Bytes(), 1024, 16)
	if err == nil {
		t.Fatalf("extractBackupTarGzWithLimits() error = nil, want unknown entry to count against total cap")
	}
	if !strings.Contains(err.Error(), "backup payload is too large") {
		t.Fatalf("extractBackupTarGzWithLimits() error = %v, want payload size error", err)
	}
}

func TestExtractBackupTarGzRejectsUnmanifestedRestoredFiles(t *testing.T) {
	files := map[string][]byte{
		"servers.db":  []byte("sqlite-snapshot"),
		"config.json": []byte(`{"encryption_key":"abc"}`),
	}
	configSum := sha256.Sum256(files["config.json"])
	manifest := backupManifest{
		Format:  backupFormatName,
		Version: backupFormatVersion,
		Files: map[string]backupManifestFile{
			"config.json": {
				Size:   int64(len(files["config.json"])),
				SHA256: hex.EncodeToString(configSum[:]),
			},
		},
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal(manifest) unexpected error: %v", err)
	}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{name: "manifest.json", data: manifestData},
		{name: "servers.db", data: files["servers.db"]},
		{name: "config.json", data: files["config.json"]},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.data))}); err != nil {
			t.Fatalf("WriteHeader(%q) unexpected error: %v", entry.name, err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			t.Fatalf("Write(%q) unexpected error: %v", entry.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close() unexpected error: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip.Close() unexpected error: %v", err)
	}

	_, _, err = extractBackupTarGzWithLimits(raw.Bytes(), 1024, 4096)
	if err == nil {
		t.Fatalf("extractBackupTarGzWithLimits() error = nil, want missing manifest entry error")
	}
	if !strings.Contains(err.Error(), "servers.db") {
		t.Fatalf("extractBackupTarGzWithLimits() error = %v, want servers.db missing from manifest", err)
	}
}

func TestApplyBackupFilesRemovesSQLiteSidecars(t *testing.T) {
	preserveServerState(t)
	preserveDBState(t)
	preserveSessionState(t)
	preserveMetricsTokenState(t)
	preserveEncryptionState(t)
	dbFile := filepath.Join(t.TempDir(), "restore-sidecars.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)

	servers = []Server{{Name: "srv-sidecar", Host: "example.org", Port: 22, User: "root", Pass: "pw"}}
	if err := saveServers(); err != nil {
		t.Fatalf("saveServers() unexpected error: %v", err)
	}
	dbSnapshot, err := createDBBackupSnapshot()
	if err != nil {
		t.Fatalf("createDBBackupSnapshot() unexpected error: %v", err)
	}
	configData, err := os.ReadFile(configPath())
	if err != nil {
		t.Fatalf("ReadFile(configPath()) unexpected error: %v", err)
	}

	resetRuntimeCaches()
	for _, sidecar := range sqliteSidecarPaths(dbFile) {
		if err := os.WriteFile(sidecar, []byte("stale sidecar"), 0600); err != nil {
			t.Fatalf("WriteFile(%s) unexpected error: %v", sidecar, err)
		}
	}

	if err := applyBackupFiles(context.Background(), map[string][]byte{
		"servers.db":  dbSnapshot,
		"config.json": configData,
	}); err != nil {
		t.Fatalf("applyBackupFiles() unexpected error: %v", err)
	}
	for _, sidecar := range sqliteSidecarPaths(dbFile) {
		data, err := os.ReadFile(sidecar)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("ReadFile(%s) unexpected error: %v", sidecar, err)
		}
		if bytes.Equal(data, []byte("stale sidecar")) {
			t.Fatalf("sidecar %s still contains stale pre-restore bytes", sidecar)
		}
	}
}

func TestBackupAPIExportRestoreLifecycle(t *testing.T) {
	preserveServerState(t)
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	preserveEncryptionState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "backup-lifecycle.db"))

	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionHandler(r)

	setupBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", setupBody)
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	sessionCookie := testSessionCookieFromRecorder(t, rec)

	if _, err := getDB().Exec(
		"INSERT INTO servers(name, host, port, user, pass_enc, key_enc, key_path, tags) VALUES(?, ?, ?, ?, '', '', '', '')",
		"before-export", "before.example", 22, "root",
	); err != nil {
		t.Fatalf("insert before-export server unexpected error: %v", err)
	}
	loadServers()

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/backup/export", bytes.NewBufferString(`{"passphrase":"very-strong-passphrase","include_known_hosts":false}`))
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("backup export status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("backup export Content-Type = %q, want %q", got, "application/octet-stream")
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, backupFileExtension) {
		t.Fatalf("backup export Content-Disposition = %q, want extension %q", got, backupFileExtension)
	}
	exportJobID := strings.TrimSpace(rec.Header().Get("X-Job-ID"))
	if exportJobID == "" {
		t.Fatalf("backup export missing X-Job-ID header")
	}
	backupBlob := append([]byte(nil), rec.Body.Bytes()...)
	if len(backupBlob) == 0 {
		t.Fatalf("backup export payload is empty")
	}
	var exportJobStatus, exportJobKind string
	if err := getDB().QueryRow("SELECT status, kind FROM jobs WHERE id = ?", exportJobID).Scan(&exportJobStatus, &exportJobKind); err != nil {
		t.Fatalf("query export job: %v", err)
	}
	if exportJobKind != jobKindBackupExport || exportJobStatus != jobStatusSucceeded {
		t.Fatalf("export job kind/status = %q/%q, want %q/%q", exportJobKind, exportJobStatus, jobKindBackupExport, jobStatusSucceeded)
	}

	if _, err := getDB().Exec(
		"INSERT INTO servers(name, host, port, user, pass_enc, key_enc, key_path, tags) VALUES(?, ?, ?, ?, '', '', '', '')",
		"after-export", "after.example", 22, "root",
	); err != nil {
		t.Fatalf("insert after-export server unexpected error: %v", err)
	}
	loadServers()

	var restoreBody bytes.Buffer
	writer := multipart.NewWriter(&restoreBody)
	part, err := writer.CreateFormFile("file", "test"+backupFileExtension)
	if err != nil {
		t.Fatalf("CreateFormFile() unexpected error: %v", err)
	}
	if _, err := part.Write(backupBlob); err != nil {
		t.Fatalf("part.Write() unexpected error: %v", err)
	}
	if err := writer.WriteField("passphrase", "very-strong-passphrase"); err != nil {
		t.Fatalf("WriteField(passphrase) unexpected error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() unexpected error: %v", err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/backup/restore", &restoreBody)
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("backup restore status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var restoreResp struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &restoreResp); err != nil {
		t.Fatalf("unmarshal restore response: %v", err)
	}
	if strings.TrimSpace(restoreResp.JobID) == "" {
		t.Fatalf("restore response missing job_id: %s", rec.Body.String())
	}

	var beforeCount int
	if err := getDB().QueryRow("SELECT COUNT(1) FROM servers WHERE name = ?", "before-export").Scan(&beforeCount); err != nil {
		t.Fatalf("query before-export count unexpected error: %v", err)
	}
	if beforeCount != 1 {
		t.Fatalf("before-export count = %d, want 1", beforeCount)
	}

	var afterCount int
	if err := getDB().QueryRow("SELECT COUNT(1) FROM servers WHERE name = ?", "after-export").Scan(&afterCount); err != nil {
		t.Fatalf("query after-export count unexpected error: %v", err)
	}
	if afterCount != 0 {
		t.Fatalf("after-export count = %d, want 0", afterCount)
	}

	var sessionCount int
	if err := getDB().QueryRow("SELECT COUNT(1) FROM sessions").Scan(&sessionCount); err != nil {
		t.Fatalf("query session count unexpected error: %v", err)
	}
	if sessionCount != 0 {
		t.Fatalf("session count after restore = %d, want 0", sessionCount)
	}
	var restoreJobStatus, restoreJobKind string
	if err := getDB().QueryRow("SELECT status, kind FROM jobs WHERE id = ?", restoreResp.JobID).Scan(&restoreJobStatus, &restoreJobKind); err != nil {
		t.Fatalf("query restore job: %v", err)
	}
	if restoreJobKind != jobKindBackupRestore || restoreJobStatus != jobStatusSucceeded {
		t.Fatalf("restore job kind/status = %q/%q, want %q/%q", restoreJobKind, restoreJobStatus, jobKindBackupRestore, jobStatusSucceeded)
	}
	var restoredExportJobs int
	if err := getDB().QueryRow("SELECT COUNT(1) FROM jobs WHERE kind = ?", jobKindBackupExport).Scan(&restoredExportJobs); err != nil {
		t.Fatalf("query restored export job count: %v", err)
	}
	if restoredExportJobs != 0 {
		t.Fatalf("restored export job count = %d, want 0", restoredExportJobs)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/backup/status", nil)
	req.AddCookie(sessionCookie)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("backup status with pre-restore session status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBackupRoutesRequireAuthentication(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	preserveEncryptionState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "backup-auth-gate.db"))

	gin.SetMode(gin.TestMode)
	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionHandler(r)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   *bytes.Buffer
	}{
		{name: "status", method: http.MethodGet, path: "/api/backup/status", body: nil},
		{name: "export", method: http.MethodPost, path: "/api/backup/export", body: bytes.NewBufferString(`{"passphrase":"very-strong-passphrase"}`)},
		{name: "restore", method: http.MethodPost, path: "/api/backup/restore", body: bytes.NewBufferString("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bodyReader io.Reader
			if tc.body != nil {
				bodyReader = bytes.NewBuffer(append([]byte(nil), tc.body.Bytes()...))
			}
			req := httptest.NewRequest(tc.method, tc.path, bodyReader)
			if tc.path == "/api/backup/export" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s unauthenticated status = %d, want %d", tc.path, rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestBackupWriteRoutesRequireSameOrigin(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	preserveEncryptionState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "backup-same-origin.db"))

	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionHandler(r)

	setupBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", setupBody)
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	sessionCookie := testSessionCookieFromRecorder(t, rec)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/backup/export", bytes.NewBufferString(`{"passphrase":"very-strong-passphrase"}`))
	req.AddCookie(sessionCookie)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("backup export without same-origin status = %d, want %d (body=%s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestBackupRoutesRejectWhileServerActionsAreActive(t *testing.T) {
	preserveServerState(t)
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	preserveEncryptionState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "backup-busy-actions.db"))

	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionHandler(r)

	setupBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", setupBody)
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	sessionCookie := testSessionCookieFromRecorder(t, rec)

	mu.Lock()
	servers = []Server{{Name: "srv-busy", Host: "example.org", Port: 22, User: "root", Pass: "pw"}}
	statusMap = map[string]*ServerStatus{
		"srv-busy": {Name: "srv-busy", Status: "pending_approval", Upgradable: []string{"openssl"}},
	}
	mu.Unlock()

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/backup/export", bytes.NewBufferString(`{"passphrase":"very-strong-passphrase"}`))
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("backup export with active action status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
	}

	var restoreBody bytes.Buffer
	writer := multipart.NewWriter(&restoreBody)
	part, err := writer.CreateFormFile("file", "test"+backupFileExtension)
	if err != nil {
		t.Fatalf("CreateFormFile() unexpected error: %v", err)
	}
	if _, err := part.Write([]byte("not-a-real-backup")); err != nil {
		t.Fatalf("part.Write() unexpected error: %v", err)
	}
	if err := writer.WriteField("passphrase", "very-strong-passphrase"); err != nil {
		t.Fatalf("WriteField(passphrase) unexpected error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() unexpected error: %v", err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/backup/restore", &restoreBody)
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("backup restore with active action status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
	}

	var jobCount int
	if err := getDB().QueryRow("SELECT COUNT(1) FROM jobs").Scan(&jobCount); err != nil {
		t.Fatalf("query jobs count: %v", err)
	}
	if jobCount != 0 {
		t.Fatalf("job count after rejected backup routes = %d, want 0", jobCount)
	}
}
