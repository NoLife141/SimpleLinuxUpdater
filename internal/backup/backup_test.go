package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

const testPassphrase = "very-strong-passphrase"

func TestValidatePassphrase(t *testing.T) {
	if err := ValidatePassphrase(testPassphrase); err != nil {
		t.Fatalf("ValidatePassphrase(valid) error = %v", err)
	}
	if err := ValidatePassphrase("short"); err != ErrInvalidPassphrase {
		t.Fatalf("ValidatePassphrase(short) error = %v, want %v", err, ErrInvalidPassphrase)
	}
}

func TestPayloadRoundTrip(t *testing.T) {
	files := map[string][]byte{
		"servers.db":  []byte("sqlite-bytes"),
		"config.json": []byte(`{"encryption_key":"test"}`),
		"known_hosts": []byte("host ssh-ed25519 AAAATEST"),
	}
	tarGz, err := BuildTarGz(files)
	if err != nil {
		t.Fatalf("BuildTarGz() error = %v", err)
	}
	encrypted, err := EncryptPayload(tarGz, testPassphrase)
	if err != nil {
		t.Fatalf("EncryptPayload() error = %v", err)
	}
	plain, err := DecryptPayload(encrypted, testPassphrase)
	if err != nil {
		t.Fatalf("DecryptPayload(valid) error = %v", err)
	}
	restored, manifest, err := ExtractTarGz(plain)
	if err != nil {
		t.Fatalf("ExtractTarGz() error = %v", err)
	}
	for name, want := range files {
		if got := restored[name]; !bytes.Equal(got, want) {
			t.Fatalf("restored %s = %q, want %q", name, got, want)
		}
	}
	if manifest.Format != FormatName || manifest.Version != FormatVersion {
		t.Fatalf("manifest format/version = %q/%d, want %q/%d", manifest.Format, manifest.Version, FormatName, FormatVersion)
	}
	if _, err := DecryptPayload(encrypted, "wrong-passphrase"); err == nil {
		t.Fatalf("DecryptPayload(wrong passphrase) error = nil, want error")
	}
}

func TestDecryptPayloadRejectsMalformedAndUnsupported(t *testing.T) {
	if _, err := DecryptPayload([]byte("not-json"), testPassphrase); err != ErrMalformed {
		t.Fatalf("DecryptPayload(malformed) error = %v, want %v", err, ErrMalformed)
	}
	raw, err := json.Marshal(Envelope{Format: "other", Version: FormatVersion})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if _, err := DecryptPayload(raw, testPassphrase); err != ErrUnsupportedFormat {
		t.Fatalf("DecryptPayload(unsupported) error = %v, want %v", err, ErrUnsupportedFormat)
	}
}

func TestExtractTarGzCountsUnknownRegularEntries(t *testing.T) {
	manifest := Manifest{
		Format:  FormatName,
		Version: FormatVersion,
		Files:   map[string]ManifestFile{},
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for name, data := range map[string][]byte{
		"unknown.bin":   []byte(strings.Repeat("x", 32)),
		"manifest.json": manifestData,
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write data: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	_, _, err = ExtractTarGzWithLimits(raw.Bytes(), 1024, 16)
	if err == nil || !strings.Contains(err.Error(), "backup payload is too large") {
		t.Fatalf("ExtractTarGzWithLimits() error = %v, want payload size error", err)
	}
}

func TestRestoreArchiveBeforeApplyRunsAfterArchiveExtraction(t *testing.T) {
	tarGz, err := BuildTarGz(map[string][]byte{
		"servers.db":  []byte("not-sqlite"),
		"config.json": []byte(`{"encryption_key":"bad"}`),
	})
	if err != nil {
		t.Fatalf("BuildTarGz() error = %v", err)
	}
	encrypted, err := EncryptPayload(tarGz, testPassphrase)
	if err != nil {
		t.Fatalf("EncryptPayload() error = %v", err)
	}

	applyStarted := false
	decodeErr := errors.New("decode failed")
	service := NewService(ServiceDeps{
		DBPath: func() string {
			return t.TempDir() + "/restore.db"
		},
		KnownHostsWritePath: func() (string, error) {
			return "", errors.New("known_hosts unavailable")
		},
		DecodeEncryptionKey: func(string) ([]byte, error) {
			return nil, decodeErr
		},
		Logf: func(string, ...any) {},
	})
	_, err = service.RestoreArchiveWithOptions(context.Background(), encrypted, testPassphrase, RestoreOptions{
		BeforeApply: func() {
			applyStarted = true
		},
	})
	if err == nil {
		t.Fatalf("RestoreArchiveWithOptions() error = nil, want apply error")
	}
	var restoreErr *RestoreError
	if !errors.As(err, &restoreErr) || restoreErr.Stage != RestoreStageApply {
		t.Fatalf("RestoreArchiveWithOptions() error = %v, want apply-stage restore error", err)
	}
	if !applyStarted {
		t.Fatalf("BeforeApply was not called before applying files")
	}
}

func TestValidateDatabaseDataRejectsMissingServersTableBeforeMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "missing-servers.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	if _, err := db.Exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"); err != nil {
		_ = db.Close()
		t.Fatalf("create settings table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read database: %v", err)
	}

	schemaCalled := false
	service := NewService(ServiceDeps{
		EnsureSchema: func(db *sql.DB) error {
			schemaCalled = true
			_, err := db.Exec(`
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
			return err
		},
		DecryptSecretWithKey: func(string, []byte) (string, error) {
			return "", nil
		},
		Logf: func(string, ...any) {},
	})
	err = service.ValidateDatabaseData(context.Background(), data, []byte("test-key"))
	if err == nil || !strings.Contains(err.Error(), "missing required table servers") {
		t.Fatalf("ValidateDatabaseData() error = %v, want missing servers table", err)
	}
	if schemaCalled {
		t.Fatalf("ValidateDatabaseData() called EnsureSchema before rejecting missing servers table")
	}
}

func TestRestoreArchiveBeforeApplySkipsOnArchiveFailure(t *testing.T) {
	applyStarted := false
	service := NewService(ServiceDeps{Logf: func(string, ...any) {}})
	_, err := service.RestoreArchiveWithOptions(context.Background(), []byte("not-json"), testPassphrase, RestoreOptions{
		BeforeApply: func() {
			applyStarted = true
		},
	})
	if err == nil {
		t.Fatalf("RestoreArchiveWithOptions() error = nil, want decrypt error")
	}
	var restoreErr *RestoreError
	if !errors.As(err, &restoreErr) || restoreErr.Stage != RestoreStageDecrypt {
		t.Fatalf("RestoreArchiveWithOptions() error = %v, want decrypt-stage restore error", err)
	}
	if applyStarted {
		t.Fatalf("BeforeApply was called before a successful decrypt/archive")
	}
}

func TestBarrierExclusiveLockBlocksReaders(t *testing.T) {
	barrier := NewBarrier()
	if !barrier.TryRLock() {
		t.Fatalf("TryRLock() = false, want true before exclusive lock")
	}
	barrier.RUnlock()
	if !barrier.TryLock() {
		t.Fatalf("TryLock() = false, want true")
	}
	if barrier.TryRLock() {
		t.Fatalf("TryRLock() = true while exclusive lock is held")
	}
	barrier.Unlock()
	if !barrier.TryRLock() {
		t.Fatalf("TryRLock() = false after exclusive lock release")
	}
	barrier.RUnlock()
}
