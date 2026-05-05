package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/scrypt"
)

const (
	backupFileExtension         = ".slubkp"
	backupFormatName            = "simplelinuxupdater-backup"
	backupFormatVersion         = 1
	backupMaxUploadBytes        = 256 * 1024 * 1024
	backupMaxExtractedBytes     = backupMaxUploadBytes
	backupMaxExportRequestBytes = 1024 * 1024
	backupMinPassphraseLength   = 12
	backupScryptN               = 32768
	backupScryptR               = 8
	backupScryptP               = 1
	backupKeyLen                = 32
)

var backupRestoreMu sync.RWMutex

var (
	errBackupInvalidPassphrase = errors.New("passphrase must be at least 12 characters")
	errBackupMalformed         = errors.New("malformed backup file")
	errBackupUnsupportedFormat = errors.New("unsupported backup format")
	errBackupMissingFile       = errors.New("backup missing required file")
)

type backupExportRequest struct {
	Passphrase        string `json:"passphrase"`
	IncludeKnownHosts *bool  `json:"include_known_hosts"`
}

type backupManifest struct {
	Format    string                        `json:"format"`
	Version   int                           `json:"version"`
	CreatedAt string                        `json:"created_at"`
	Files     map[string]backupManifestFile `json:"files"`
}

type backupManifestFile struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type backupKDFSpec struct {
	Name    string `json:"name"`
	N       int    `json:"N"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	SaltB64 string `json:"salt_b64"`
}

type backupCipherSpec struct {
	Name     string `json:"name"`
	NonceB64 string `json:"nonce_b64"`
}

type backupEnvelope struct {
	Format     string           `json:"format"`
	Version    int              `json:"version"`
	CreatedAt  string           `json:"created_at"`
	KDF        backupKDFSpec    `json:"kdf"`
	Cipher     backupCipherSpec `json:"cipher"`
	PayloadB64 string           `json:"payload_b64"`
}

type backupStatusResponse struct {
	DBPath           string `json:"db_path"`
	ConfigPath       string `json:"config_path"`
	KnownHostsPath   string `json:"known_hosts_path"`
	KnownHostsExists bool   `json:"known_hosts_exists"`
}

type restoreSnapshot struct {
	Path   string
	Exists bool
	Data   []byte
}

func expireSessionCookie(c *gin.Context) {
	if c == nil {
		return
	}
	sm := currentSessionManager()
	if sm == nil {
		return
	}
	if sm.Cookie.SameSite == http.SameSiteDefaultMode {
		c.SetCookie(sm.Cookie.Name, "", -1, sm.Cookie.Path, sm.Cookie.Domain, sm.Cookie.Secure, sm.Cookie.HttpOnly)
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sm.Cookie.Name,
		Value:    "",
		Domain:   sm.Cookie.Domain,
		Path:     sm.Cookie.Path,
		MaxAge:   -1,
		HttpOnly: sm.Cookie.HttpOnly,
		Secure:   sm.Cookie.Secure,
		SameSite: sm.Cookie.SameSite,
	})
}

func validateBackupPassphrase(passphrase string) error {
	if len(strings.TrimSpace(passphrase)) < backupMinPassphraseLength {
		return errBackupInvalidPassphrase
	}
	return nil
}

func validateBackupSnapshotPath(path string) error {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" || !filepath.IsAbs(cleanPath) {
		return errors.New("invalid backup snapshot path")
	}
	if strings.ContainsRune(cleanPath, '\'') || strings.ContainsAny(cleanPath, "\r\n") {
		return errors.New("invalid backup snapshot path")
	}
	tempRoot := filepath.Clean(os.TempDir())
	rel, err := filepath.Rel(tempRoot, cleanPath)
	if err != nil {
		return errors.New("invalid backup snapshot path")
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return errors.New("invalid backup snapshot path")
	}
	return nil
}

func createDBBackupSnapshot() ([]byte, error) {
	tmp, err := os.CreateTemp("", "slu-backup-db-*.sqlite")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	defer os.Remove(tmpPath)
	if err := validateBackupSnapshotPath(tmpPath); err != nil {
		return nil, err
	}

	// SQLite VACUUM INTO does not accept bind parameters. This is safe because tmpPath
	// comes from os.CreateTemp and validateBackupSnapshotPath enforces absolute temp-root
	// location and rejects quotes/newlines before SQL assembly.
	vacuumSQL := "VACUUM INTO '" + tmpPath + "'"
	if _, err := getDB().Exec(vacuumSQL); err != nil {
		return nil, fmt.Errorf("snapshot database: %w", err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read db snapshot: %w", err)
	}
	return data, nil
}

func knownHostsBackupPath() (string, bool) {
	if p, err := knownHostsWritePath(); err == nil {
		if st, statErr := os.Stat(p); statErr == nil && !st.IsDir() {
			return p, true
		}
	}
	defaultPath := filepath.Join(filepath.Dir(dbPath()), "known_hosts")
	if st, err := os.Stat(defaultPath); err == nil && !st.IsDir() {
		return defaultPath, true
	}
	return defaultPath, false
}

func buildBackupTarGz(files map[string][]byte) ([]byte, error) {
	manifest := backupManifest{
		Format:    backupFormatName,
		Version:   backupFormatVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Files:     make(map[string]backupManifestFile, len(files)),
	}

	for name, data := range files {
		sum := sha256.Sum256(data)
		manifest.Files[name] = backupManifestFile{
			Size:   int64(len(data)),
			SHA256: hex.EncodeToString(sum[:]),
		}
	}

	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	files["manifest.json"] = manifestData

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)

	for _, name := range []string{"manifest.json", "servers.db", "config.json", "known_hosts"} {
		data, ok := files[name]
		if !ok {
			continue
		}
		hdr := &tar.Header{
			Name:    name,
			Mode:    0600,
			Size:    int64(len(data)),
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return raw.Bytes(), nil
}

func encryptBackupPayload(plain []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, backupScryptN, backupScryptR, backupScryptP, backupKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	env := backupEnvelope{
		Format:    backupFormatName,
		Version:   backupFormatVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		KDF: backupKDFSpec{
			Name:    "scrypt",
			N:       backupScryptN,
			R:       backupScryptR,
			P:       backupScryptP,
			SaltB64: base64.StdEncoding.EncodeToString(salt),
		},
		Cipher: backupCipherSpec{
			Name:     "aes-256-gcm",
			NonceB64: base64.StdEncoding.EncodeToString(nonce),
		},
		PayloadB64: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.Marshal(env)
}

func decryptBackupPayload(encrypted []byte, passphrase string) ([]byte, error) {
	var env backupEnvelope
	if err := json.Unmarshal(encrypted, &env); err != nil {
		return nil, errBackupMalformed
	}
	if env.Format != backupFormatName || env.Version != backupFormatVersion {
		return nil, errBackupUnsupportedFormat
	}
	if env.KDF.Name != "scrypt" || env.Cipher.Name != "aes-256-gcm" {
		return nil, errBackupUnsupportedFormat
	}
	if env.KDF.N <= 0 || env.KDF.R <= 0 || env.KDF.P <= 0 {
		return nil, errBackupUnsupportedFormat
	}
	if env.KDF.N != backupScryptN || env.KDF.R != backupScryptR || env.KDF.P != backupScryptP {
		return nil, errBackupUnsupportedFormat
	}
	salt, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.KDF.SaltB64))
	if err != nil || len(salt) == 0 {
		return nil, errBackupMalformed
	}
	nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.Cipher.NonceB64))
	if err != nil || len(nonce) != 12 {
		return nil, errBackupMalformed
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.PayloadB64))
	if err != nil || len(ciphertext) == 0 {
		return nil, errBackupMalformed
	}
	key, err := scrypt.Key([]byte(passphrase), salt, backupScryptN, backupScryptR, backupScryptP, backupKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("decryptBackupPayload: gcm open failed: %v", err)
		return nil, errors.New("invalid passphrase or corrupted backup")
	}
	return plain, nil
}

func extractBackupTarGz(payload []byte) (map[string][]byte, backupManifest, error) {
	return extractBackupTarGzWithLimits(payload, backupMaxUploadBytes, backupMaxExtractedBytes)
}

func extractBackupTarGzWithLimits(payload []byte, maxFileBytes, maxTotalBytes int64) (map[string][]byte, backupManifest, error) {
	files := make(map[string][]byte)
	var totalExtracted int64
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, backupManifest{}, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, backupManifest{}, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size < 0 || hdr.Size > maxFileBytes {
			return nil, backupManifest{}, fmt.Errorf("%w: backup entry %q is too large", errBackupMalformed, hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFileBytes+1))
		if err != nil {
			return nil, backupManifest{}, err
		}
		if int64(len(data)) > maxFileBytes {
			return nil, backupManifest{}, fmt.Errorf("%w: backup entry %q is too large", errBackupMalformed, hdr.Name)
		}
		if totalExtracted+int64(len(data)) > maxTotalBytes {
			return nil, backupManifest{}, fmt.Errorf("%w: backup payload is too large", errBackupMalformed)
		}
		totalExtracted += int64(len(data))
		name := filepath.Base(strings.TrimSpace(hdr.Name))
		if name == "" {
			continue
		}
		if name != "manifest.json" && name != "servers.db" && name != "config.json" && name != "known_hosts" {
			continue
		}
		files[name] = data
	}

	manifestData, ok := files["manifest.json"]
	if !ok {
		return nil, backupManifest{}, errBackupMalformed
	}
	var manifest backupManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, backupManifest{}, errBackupMalformed
	}
	if manifest.Format != backupFormatName || manifest.Version != backupFormatVersion {
		return nil, backupManifest{}, errBackupUnsupportedFormat
	}
	if manifest.Files == nil {
		return nil, backupManifest{}, errBackupMalformed
	}
	for _, name := range []string{"servers.db", "config.json"} {
		if _, ok := files[name]; !ok {
			return nil, backupManifest{}, fmt.Errorf("%w: %s", errBackupMissingFile, name)
		}
		if _, ok := manifest.Files[name]; !ok {
			return nil, backupManifest{}, fmt.Errorf("%w: %s", errBackupMissingFile, name)
		}
	}
	if _, ok := files["known_hosts"]; ok {
		if _, ok := manifest.Files["known_hosts"]; !ok {
			return nil, backupManifest{}, fmt.Errorf("%w: known_hosts", errBackupMissingFile)
		}
	}
	for name, meta := range manifest.Files {
		if name != "servers.db" && name != "config.json" && name != "known_hosts" {
			return nil, backupManifest{}, fmt.Errorf("%w: unexpected file %s", errBackupMalformed, name)
		}
		data, exists := files[name]
		if !exists {
			return nil, backupManifest{}, fmt.Errorf("%w: %s", errBackupMissingFile, name)
		}
		if int64(len(data)) != meta.Size {
			return nil, backupManifest{}, fmt.Errorf("checksum size mismatch for %s", name)
		}
		sum := sha256.Sum256(data)
		if !strings.EqualFold(meta.SHA256, hex.EncodeToString(sum[:])) {
			return nil, backupManifest{}, fmt.Errorf("checksum mismatch for %s", name)
		}
	}
	return files, manifest, nil
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	if err := ensurePrivateDirForFile(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".restore-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func persistActiveMaintenanceStateForRestore() error {
	state := currentMaintenanceState()
	if !state.Active {
		return nil
	}
	if err := persistMaintenanceState(state); err != nil {
		return fmt.Errorf("persist active maintenance marker in restored database: %w", err)
	}
	return nil
}

func snapshotExistingFiles(paths []string) (map[string]restoreSnapshot, error) {
	out := make(map[string]restoreSnapshot, len(paths))
	for _, p := range paths {
		st := restoreSnapshot{Path: p, Exists: false}
		data, err := os.ReadFile(p)
		if err == nil {
			st.Exists = true
			st.Data = data
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		out[p] = st
	}
	return out, nil
}

func restoreSnapshots(snaps map[string]restoreSnapshot) error {
	for _, snap := range snaps {
		if snap.Exists {
			if err := writeAtomicFile(snap.Path, snap.Data, 0600); err != nil {
				return err
			}
			continue
		}
		if err := os.Remove(snap.Path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func sqliteSidecarPaths(path string) []string {
	return []string{path + "-wal", path + "-shm"}
}

func removeSQLiteSidecars(path string) error {
	for _, sidecar := range sqliteSidecarPaths(path) {
		if err := os.Remove(sidecar); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func validateBackupConfigData(data []byte) ([]byte, error) {
	var cfg map[string]string
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse restored config: %w", err)
	}
	key, err := decodeEncryptionKeyValue(cfg["encryption_key"])
	if err != nil {
		return nil, fmt.Errorf("invalid restored encryption_key: %w", err)
	}
	return key, nil
}

func validateBackupDatabaseData(ctx context.Context, data []byte, encryptionKey []byte) error {
	tmp, err := os.CreateTemp("", "slu-restore-validate-*.sqlite")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return fmt.Errorf("open restored database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", sqliteBusyTimeoutMS)); err != nil {
		return fmt.Errorf("set restored database busy_timeout: %w", err)
	}
	if err := ensureSchema(db); err != nil {
		return fmt.Errorf("validate restored database schema: %w", err)
	}

	rows, err := db.QueryContext(ctx, "SELECT name, pass_enc, key_enc FROM servers ORDER BY name")
	if err != nil {
		return fmt.Errorf("validate restored servers: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, passEnc, keyEnc string
		if err := rows.Scan(&name, &passEnc, &keyEnc); err != nil {
			return fmt.Errorf("scan restored server: %w", err)
		}
		if _, err := decryptSecretWithKey(passEnc, encryptionKey); err != nil {
			return fmt.Errorf("decrypt restored password for %s: %w", name, err)
		}
		if _, err := decryptSecretWithKey(keyEnc, encryptionKey); err != nil {
			return fmt.Errorf("decrypt restored SSH key for %s: %w", name, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read restored servers: %w", err)
	}

	var globalKeyEnc string
	err = db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", globalKeySetting).Scan(&globalKeyEnc)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read restored global SSH key: %w", err)
	}
	if err == nil && strings.TrimSpace(globalKeyEnc) != "" {
		if _, err := decryptSecretWithKey(globalKeyEnc, encryptionKey); err != nil {
			return fmt.Errorf("decrypt restored global SSH key: %w", err)
		}
	}
	return nil
}

func reencryptBackupDatabaseData(ctx context.Context, data []byte, fromKey, toKey []byte) ([]byte, error) {
	if bytes.Equal(fromKey, toKey) {
		return append([]byte(nil), data...), nil
	}
	tmp, err := os.CreateTemp("", "slu-restore-rewrap-*.sqlite")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, fmt.Errorf("open restored database for rewrap: %w", err)
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", sqliteBusyTimeoutMS)); err != nil {
		return nil, fmt.Errorf("set restored database rewrap busy_timeout: %w", err)
	}
	if err := ensureSchema(db); err != nil {
		return nil, fmt.Errorf("prepare restored database rewrap schema: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin restored database rewrap: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	type encryptedServerSecrets struct {
		name    string
		passEnc string
		keyEnc  string
	}
	rows, err := tx.QueryContext(ctx, "SELECT name, pass_enc, key_enc FROM servers ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("read restored server secrets for rewrap: %w", err)
	}
	var secretRows []encryptedServerSecrets
	for rows.Next() {
		var row encryptedServerSecrets
		if err := rows.Scan(&row.name, &row.passEnc, &row.keyEnc); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan restored server secret for rewrap: %w", err)
		}
		secretRows = append(secretRows, row)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close restored server secret rows for rewrap: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read restored server secret rows for rewrap: %w", err)
	}

	updateServerStmt, err := tx.PrepareContext(ctx, "UPDATE servers SET pass_enc = ?, key_enc = ? WHERE name = ?")
	if err != nil {
		return nil, fmt.Errorf("prepare restored server secret rewrap: %w", err)
	}
	defer func() {
		if updateServerStmt != nil {
			_ = updateServerStmt.Close()
		}
	}()
	for _, row := range secretRows {
		pass, err := decryptSecretWithKey(row.passEnc, fromKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt restored password for %s during rewrap: %w", row.name, err)
		}
		passEnc, err := encryptSecretWithKey(pass, toKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt restored password for %s during rewrap: %w", row.name, err)
		}
		key, err := decryptSecretWithKey(row.keyEnc, fromKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt restored SSH key for %s during rewrap: %w", row.name, err)
		}
		keyEnc, err := encryptSecretWithKey(key, toKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt restored SSH key for %s during rewrap: %w", row.name, err)
		}
		if _, err := updateServerStmt.ExecContext(ctx, passEnc, keyEnc, row.name); err != nil {
			return nil, fmt.Errorf("update restored server secret for %s during rewrap: %w", row.name, err)
		}
	}
	if err := updateServerStmt.Close(); err != nil {
		return nil, fmt.Errorf("close restored server secret rewrap statement: %w", err)
	}
	updateServerStmt = nil

	var globalKeyEnc string
	err = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", globalKeySetting).Scan(&globalKeyEnc)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read restored global SSH key for rewrap: %w", err)
	}
	if err == nil && strings.TrimSpace(globalKeyEnc) != "" {
		globalKey, err := decryptSecretWithKey(globalKeyEnc, fromKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt restored global SSH key during rewrap: %w", err)
		}
		rewrappedGlobalKey, err := encryptSecretWithKey(globalKey, toKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt restored global SSH key during rewrap: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE settings SET value = ? WHERE key = ?", rewrappedGlobalKey, globalKeySetting); err != nil {
			return nil, fmt.Errorf("update restored global SSH key during rewrap: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit restored database rewrap: %w", err)
	}
	committed = true
	if err := db.Close(); err != nil {
		return nil, fmt.Errorf("close restored database after rewrap: %w", err)
	}
	db = nil
	return os.ReadFile(tmpPath)
}

func prepareBackupRuntimeFiles(ctx context.Context, files map[string][]byte) (map[string][]byte, error) {
	backupKey, err := validateBackupConfigData(files["config.json"])
	if err != nil {
		return nil, err
	}
	if err := validateBackupDatabaseData(ctx, files["servers.db"], backupKey); err != nil {
		return nil, err
	}
	rewrappedDB, err := reencryptBackupDatabaseData(ctx, files["servers.db"], backupKey, getEncryptionKey())
	if err != nil {
		return nil, err
	}
	prepared := make(map[string][]byte, len(files))
	for name, data := range files {
		prepared[name] = data
	}
	prepared["servers.db"] = rewrappedDB
	return prepared, nil
}

func resetRuntimeCaches() {
	runtimeStateMu.Lock()
	defer runtimeStateMu.Unlock()
	if db != nil {
		_ = db.Close()
	}
	db = nil
	dbOnce = sync.Once{}

	encryptionKey = nil
	keyOnce = sync.Once{}

	globalKeyMu.Lock()
	globalKey = ""
	globalKeyMu.Unlock()

	metricsBearerTokenHashMu.Lock()
	metricsBearerTokenHash = ""
	metricsBearerTokenHashLoaded = false
	metricsBearerTokenHashDBPath = ""
	metricsBearerTokenHashMu.Unlock()

	setCurrentJobManager(nil)
}

func reloadRuntimeState() error {
	_ = getDB()
	maintenanceActive := currentMaintenanceState().Active
	if !maintenanceActive {
		if err := initializeMaintenanceState(); err != nil {
			return err
		}
	}
	if err := initializeJobManager(); err != nil {
		return err
	}
	loadServers()
	mu.Lock()
	statusMap = make(map[string]*ServerStatus, len(servers))
	for _, s := range servers {
		statusMap[s.Name] = &ServerStatus{
			Name:           s.Name,
			Host:           s.Host,
			Port:           normalizePort(s.Port),
			User:           s.User,
			Status:         "idle",
			Logs:           "",
			Upgradable:     []string{},
			PendingUpdates: []PendingUpdate{},
			HasPassword:    s.Pass != "",
			HasKey:         s.Key != "",
			Tags:           append([]string(nil), s.Tags...),
		}
	}
	mu.Unlock()
	_ = getGlobalKey()
	_ = getMetricsBearerTokenHash()
	sm, err := newSessionManager(getDB())
	if err != nil {
		return err
	}
	sessionManagerMu.Lock()
	sessionManager = sm
	sessionManagerMu.Unlock()
	return nil
}

func clearPersistedSessions() error {
	db := getDB()
	if _, err := db.Exec("DELETE FROM sessions"); err != nil {
		return fmt.Errorf("clear sessions: %w", err)
	}
	return nil
}

func applyBackupFiles(ctx context.Context, files map[string][]byte) error {
	dbTarget := dbPath()
	knownHostsTarget := filepath.Join(filepath.Dir(dbPath()), "known_hosts")
	if p, err := knownHostsWritePath(); err == nil && strings.TrimSpace(p) != "" {
		knownHostsTarget = p
	}
	files, err := prepareBackupRuntimeFiles(ctx, files)
	if err != nil {
		return err
	}

	targets := []string{dbTarget}
	targets = append(targets, sqliteSidecarPaths(dbTarget)...)
	if _, ok := files["known_hosts"]; ok {
		targets = append(targets, knownHostsTarget)
	}

	snaps, err := snapshotExistingFiles(targets)
	if err != nil {
		return err
	}

	resetRuntimeCaches()

	rollback := func(cause error) error {
		errs := []error{cause}
		if restoreErr := restoreSnapshots(snaps); restoreErr != nil {
			errs = append(errs, fmt.Errorf("rollback restore snapshots: %w", restoreErr))
		}
		resetRuntimeCaches()
		if reloadErr := reloadRuntimeState(); reloadErr != nil {
			errs = append(errs, fmt.Errorf("rollback reload runtime state after reset: %w", reloadErr))
		}
		return errors.Join(errs...)
	}

	if err := removeSQLiteSidecars(dbTarget); err != nil {
		return rollback(err)
	}
	if err := writeAtomicFile(dbTarget, files["servers.db"], 0600); err != nil {
		return rollback(err)
	}
	if err := removeSQLiteSidecars(dbTarget); err != nil {
		return rollback(err)
	}
	if khData, ok := files["known_hosts"]; ok {
		if err := writeAtomicFile(knownHostsTarget, khData, 0600); err != nil {
			return rollback(err)
		}
	}
	if err := persistActiveMaintenanceStateForRestore(); err != nil {
		return rollback(err)
	}
	if err := reloadRuntimeState(); err != nil {
		return rollback(err)
	}
	if err := clearPersistedSessions(); err != nil {
		return rollback(err)
	}
	return nil
}

func hasPersistedGlobalKey() (bool, error) {
	db := getDB()
	var enc string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ?", globalKeySetting).Scan(&enc)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(enc) != "", nil
}

func handleBackupStatus(c *gin.Context) {
	khPath, khExists := knownHostsBackupPath()
	c.JSON(http.StatusOK, backupStatusResponse{
		DBPath:           dbPath(),
		ConfigPath:       configPath(),
		KnownHostsPath:   khPath,
		KnownHostsExists: khExists,
	})
}

func handleBackupExport(c *gin.Context) {
	actor := actorFromContext(c)
	clientIP := clientIPFromContext(c)
	var req backupExportRequest
	if c.Request != nil && c.Writer != nil {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, backupMaxExportRequestBytes)
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		audit(c, "backup.export", "backup", "state", "failure", "Invalid backup export payload", nil)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request payload too large"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}
	req.Passphrase = strings.TrimSpace(req.Passphrase)
	if err := validateBackupPassphrase(req.Passphrase); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	includeKnownHosts := true
	if req.IncludeKnownHosts != nil {
		includeKnownHosts = *req.IncludeKnownHosts
	}
	if activeServers := activeServerActionNames(); len(activeServers) > 0 {
		audit(c, "backup.export", "backup", "state", "failure", "Active server actions must finish before export", map[string]any{
			"active_servers": activeServers,
		})
		c.JSON(http.StatusConflict, gin.H{
			"error":          "wait for active server actions to finish before starting backup export",
			"active_servers": activeServers,
		})
		return
	}

	dbSnapshot, err := createDBBackupSnapshot()
	if err != nil {
		audit(c, "backup.export", "backup", "state", "failure", "Failed to snapshot database", map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to snapshot database"})
		return
	}
	jm := currentJobManager()
	if jm == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "job manager unavailable"})
		return
	}
	job, err := jm.CreateJob(JobCreateParams{
		Kind:      jobKindBackupExport,
		Actor:     actor,
		ClientIP:  clientIP,
		Status:    jobStatusRunning,
		Phase:     jobPhaseSnapshot,
		Summary:   "Preparing backup export",
		StartedAt: jobTimestampNow(),
	})
	if err != nil {
		if errors.Is(err, errMaintenanceModeActive) {
			writeMaintenanceBlockedResponse(c)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create backup export job"})
		return
	}
	if err := activateMaintenance(jobKindBackupExport, job.ID, actor, "Backup export in progress. The application will reopen when the encrypted archive is ready."); err != nil {
		log.Printf("handleBackupExport: activateMaintenance failed for job %q: %v", job.ID, err)
		status := jobStatusFailed
		summary := "Failed to activate maintenance mode"
		errorClass := "maintenance"
		finishedAt := jobTimestampNow()
		_ = jm.UpdateJob(job.ID, JobUpdate{
			Status:     &status,
			Summary:    &summary,
			ErrorClass: &errorClass,
			FinishedAt: &finishedAt,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to activate maintenance mode"})
		return
	}
	defer func() {
		if err := deactivateMaintenance(); err != nil {
			log.Printf("handleBackupExport: failed to clear maintenance mode: %v", err)
		}
	}()
	c.Header("X-Job-ID", job.ID)
	_ = getEncryptionKey()
	configData, err := os.ReadFile(configPath())
	if err != nil {
		status := jobStatusFailed
		summary := "Failed to read config"
		errorClass := "config"
		finishedAt := jobTimestampNow()
		_ = jm.UpdateJob(job.ID, JobUpdate{
			Status:     &status,
			Summary:    &summary,
			ErrorClass: &errorClass,
			FinishedAt: &finishedAt,
		})
		audit(c, "backup.export", "backup", "state", "failure", "Failed to read config", map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read config"})
		return
	}

	files := map[string][]byte{
		"servers.db":  dbSnapshot,
		"config.json": configData,
	}
	knownHostsIncluded := false
	if includeKnownHosts {
		if path, exists := knownHostsBackupPath(); exists {
			if data, readErr := os.ReadFile(path); readErr == nil {
				files["known_hosts"] = data
				knownHostsIncluded = true
			}
		}
	}

	phase := jobPhaseEncrypt
	summary := "Encrypting backup payload"
	_ = jm.UpdateJob(job.ID, JobUpdate{Phase: &phase, Summary: &summary})
	tarGz, err := buildBackupTarGz(files)
	if err != nil {
		status := jobStatusFailed
		summary := "Failed to build backup payload"
		errorClass := "archive"
		finishedAt := jobTimestampNow()
		_ = jm.UpdateJob(job.ID, JobUpdate{
			Status:     &status,
			Summary:    &summary,
			ErrorClass: &errorClass,
			FinishedAt: &finishedAt,
		})
		audit(c, "backup.export", "backup", "state", "failure", "Failed to build backup payload", map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build backup"})
		return
	}
	encrypted, err := encryptBackupPayload(tarGz, req.Passphrase)
	if err != nil {
		status := jobStatusFailed
		summary := "Failed to encrypt backup payload"
		errorClass := "encrypt"
		finishedAt := jobTimestampNow()
		_ = jm.UpdateJob(job.ID, JobUpdate{
			Status:     &status,
			Summary:    &summary,
			ErrorClass: &errorClass,
			FinishedAt: &finishedAt,
		})
		audit(c, "backup.export", "backup", "state", "failure", "Failed to encrypt backup", map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt backup"})
		return
	}

	status := jobStatusSucceeded
	phase = jobPhaseComplete
	summary = "Backup export completed"
	finishedAt := jobTimestampNow()
	meta := marshalJobJSON(map[string]any{
		"bytes":                len(encrypted),
		"known_hosts_included": knownHostsIncluded,
	})
	_ = jm.UpdateJob(job.ID, JobUpdate{
		Status:     &status,
		Phase:      &phase,
		Summary:    &summary,
		MetaJSON:   &meta,
		FinishedAt: &finishedAt,
	})
	filename := fmt.Sprintf("simplelinuxupdater-backup-%s%s", time.Now().UTC().Format("20060102T150405Z"), backupFileExtension)
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/octet-stream", encrypted)
	audit(c, "backup.export", "backup", "state", "success", "Backup exported", map[string]any{"bytes": len(encrypted), "known_hosts_included": knownHostsIncluded})
}

func readUploadedBackupFile(file *multipart.FileHeader) ([]byte, error) {
	if file == nil {
		return nil, errors.New("missing backup file")
	}
	if file.Size > backupMaxUploadBytes {
		return nil, fmt.Errorf("backup file too large (max %d bytes)", backupMaxUploadBytes)
	}
	src, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer src.Close()
	data, err := io.ReadAll(io.LimitReader(src, backupMaxUploadBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > backupMaxUploadBytes {
		return nil, fmt.Errorf("backup file too large (max %d bytes)", backupMaxUploadBytes)
	}
	if len(data) == 0 {
		return nil, errors.New("empty backup file")
	}
	return data, nil
}

func handleBackupRestore(c *gin.Context) {
	actor := actorFromContext(c)
	clientIP := clientIPFromContext(c)
	if c.Request != nil && c.Writer != nil {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, backupMaxUploadBytes+1024)
	}
	passphrase := strings.TrimSpace(c.PostForm("passphrase"))
	if err := validateBackupPassphrase(passphrase); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	file, err := c.FormFile("file")
	if err != nil {
		audit(c, "backup.restore", "backup", "state", "failure", "Missing backup file", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": "backup file is required"})
		return
	}
	blob, err := readUploadedBackupFile(file)
	if err != nil {
		audit(c, "backup.restore", "backup", "state", "failure", "Invalid backup file", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if activeServers := activeServerActionNames(); len(activeServers) > 0 {
		audit(c, "backup.restore", "backup", "state", "failure", "Active server actions must finish before restore", map[string]any{
			"active_servers": activeServers,
		})
		c.JSON(http.StatusConflict, gin.H{
			"error":          "wait for active server actions to finish before starting backup restore",
			"active_servers": activeServers,
		})
		return
	}

	jm := currentJobManager()
	if jm == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "job manager unavailable"})
		return
	}
	job, err := jm.CreateJob(JobCreateParams{
		Kind:      jobKindBackupRestore,
		Actor:     actor,
		ClientIP:  clientIP,
		Status:    jobStatusRunning,
		Phase:     jobPhaseDecrypt,
		Summary:   "Restoring backup archive",
		StartedAt: jobTimestampNow(),
	})
	if err != nil {
		if errors.Is(err, errMaintenanceModeActive) {
			writeMaintenanceBlockedResponse(c)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create backup restore job"})
		return
	}
	if err := activateMaintenance(jobKindBackupRestore, job.ID, actor, "Backup restore in progress. Requests are paused until the restored state is ready."); err != nil {
		status := jobStatusFailed
		summary := "Failed to activate maintenance mode"
		errorClass := "maintenance"
		finishedAt := jobTimestampNow()
		_ = jm.UpdateJob(job.ID, JobUpdate{
			Status:     &status,
			Summary:    &summary,
			ErrorClass: &errorClass,
			FinishedAt: &finishedAt,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to activate maintenance mode"})
		return
	}
	defer func() {
		if err := deactivateMaintenance(); err != nil {
			log.Printf("handleBackupRestore: failed to clear maintenance mode: %v", err)
		}
	}()
	c.Header("X-Job-ID", job.ID)

	plain, err := decryptBackupPayload(blob, passphrase)
	if err != nil {
		status := jobStatusFailed
		summary := "Failed to decrypt backup archive"
		errorClass := "decrypt"
		finishedAt := jobTimestampNow()
		_ = jm.UpdateJob(job.ID, JobUpdate{
			Status:     &status,
			Summary:    &summary,
			ErrorClass: &errorClass,
			FinishedAt: &finishedAt,
		})
		audit(c, "backup.restore", "backup", "state", "failure", "Failed to decrypt backup", map[string]any{"error": err.Error()})
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to decrypt backup"})
		return
	}
	files, manifest, err := extractBackupTarGz(plain)
	if err != nil {
		status := jobStatusFailed
		summary := "Invalid backup payload"
		errorClass := "archive"
		finishedAt := jobTimestampNow()
		_ = jm.UpdateJob(job.ID, JobUpdate{
			Status:     &status,
			Summary:    &summary,
			ErrorClass: &errorClass,
			FinishedAt: &finishedAt,
		})
		audit(c, "backup.restore", "backup", "state", "failure", "Invalid backup payload", map[string]any{"error": err.Error()})
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid backup payload"})
		return
	}
	phase := jobPhaseApply
	summary := "Applying restored backup files"
	_ = jm.UpdateJob(job.ID, JobUpdate{Phase: &phase, Summary: &summary})
	restoreCtx := context.Background()
	if c.Request != nil {
		restoreCtx = c.Request.Context()
	}
	if err := applyBackupFiles(restoreCtx, files); err != nil {
		jm = currentJobManager()
		if persistErr := persistMaintenanceState(currentMaintenanceState()); persistErr != nil {
			log.Printf("handleBackupRestore: failed to re-persist active maintenance state after restore error: %v", persistErr)
		}
		status := jobStatusFailed
		summary := "Failed to apply backup files"
		errorClass := "apply"
		finishedAt := jobTimestampNow()
		if jm != nil {
			job.Status = status
			job.Phase = jobPhaseComplete
			job.Summary = summary
			job.ErrorClass = errorClass
			job.FinishedAt = finishedAt
			_ = jm.UpsertJobRecord(job)
		}
		audit(c, "backup.restore", "backup", "state", "failure", "Failed to apply backup", map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to apply backup"})
		return
	}
	jm = currentJobManager()
	if persistErr := persistMaintenanceState(currentMaintenanceState()); persistErr != nil {
		log.Printf("handleBackupRestore: failed to re-persist active maintenance state after restore: %v", persistErr)
	}

	globalKeyPresent, globalKeyErr := hasPersistedGlobalKey()
	if globalKeyErr != nil {
		log.Printf("handleBackupRestore: failed to read global key presence after restore: %v", globalKeyErr)
	}
	_, knownHostsRestored := files["known_hosts"]
	audit(c, "backup.restore", "backup", "state", "success", "Backup restored", map[string]any{
		"manifest_files":       len(manifest.Files),
		"global_key_present":   globalKeyPresent,
		"known_hosts_restored": knownHostsRestored,
	})
	expireSessionCookie(c)
	status := jobStatusSucceeded
	phase = jobPhaseComplete
	summary = "Backup restore completed"
	finishedAt := jobTimestampNow()
	meta := marshalJobJSON(map[string]any{
		"manifest_files":       len(manifest.Files),
		"global_key_present":   globalKeyPresent,
		"known_hosts_restored": knownHostsRestored,
		"sessions_invalidated": true,
	})
	if jm != nil {
		job.Status = status
		job.Phase = phase
		job.Summary = summary
		job.MetaJSON = meta
		job.FinishedAt = finishedAt
		_ = jm.UpsertJobRecord(job)
	}
	c.JSON(http.StatusOK, gin.H{
		"message":              "backup restored",
		"job_id":               job.ID,
		"restart_required":     false,
		"sessions_invalidated": true,
		"global_key_present":   globalKeyPresent,
		"known_hosts_restored": knownHostsRestored,
	})
}
