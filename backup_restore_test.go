package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
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
