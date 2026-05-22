package backup

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	FileExtension         = ".slubkp"
	FormatName            = "simplelinuxupdater-backup"
	FormatVersion         = 1
	MaxUploadBytes        = 256 * 1024 * 1024
	MaxExtractedBytes     = MaxUploadBytes
	MaxExportRequestBytes = 1024 * 1024
	MinPassphraseLength   = 12
	ScryptN               = 32768
	ScryptR               = 8
	ScryptP               = 1
	KeyLen                = 32
)

var (
	ErrInvalidPassphrase = errors.New("passphrase must be at least 12 characters")
	ErrMalformed         = errors.New("malformed backup file")
	ErrUnsupportedFormat = errors.New("unsupported backup format")
	ErrMissingFile       = errors.New("backup missing required file")
)

type ExportRequest struct {
	Passphrase        string `json:"passphrase"`
	IncludeKnownHosts *bool  `json:"include_known_hosts"`
	DBSnapshot        []byte `json:"-"`
}

type StatusResponse struct {
	DBPath           string `json:"db_path"`
	ConfigPath       string `json:"config_path"`
	KnownHostsPath   string `json:"known_hosts_path"`
	KnownHostsExists bool   `json:"known_hosts_exists"`
}

type Manifest struct {
	Format    string                  `json:"format"`
	Version   int                     `json:"version"`
	CreatedAt string                  `json:"created_at"`
	Files     map[string]ManifestFile `json:"files"`
}

type ManifestFile struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type KDFSpec struct {
	Name    string `json:"name"`
	N       int    `json:"N"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	SaltB64 string `json:"salt_b64"`
}

type CipherSpec struct {
	Name     string `json:"name"`
	NonceB64 string `json:"nonce_b64"`
}

type Envelope struct {
	Format     string     `json:"format"`
	Version    int        `json:"version"`
	CreatedAt  string     `json:"created_at"`
	KDF        KDFSpec    `json:"kdf"`
	Cipher     CipherSpec `json:"cipher"`
	PayloadB64 string     `json:"payload_b64"`
}

type RestoreSnapshot struct {
	Path   string
	Exists bool
	Data   []byte
}

type MaintenanceState struct {
	Active    bool   `json:"active"`
	Kind      string `json:"kind"`
	JobID     string `json:"job_id"`
	StartedAt string `json:"started_at"`
	Actor     string `json:"actor"`
	Message   string `json:"message"`
}

type ExportResult struct {
	Bytes              []byte
	KnownHostsIncluded bool
}

type RestoreResult struct {
	Manifest            Manifest
	GlobalKeyPresent    bool
	KnownHostsRestored  bool
	SessionsInvalidated bool
}

type RestoreOptions struct {
	BeforeApply func()
}

type ExportStage string

const (
	ExportStageSnapshot ExportStage = "snapshot"
	ExportStageConfig   ExportStage = "config"
	ExportStageArchive  ExportStage = "archive"
	ExportStageEncrypt  ExportStage = "encrypt"
)

type ExportError struct {
	Stage ExportStage
	Err   error
}

func (e *ExportError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExportError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type RestoreStage string

const (
	RestoreStageDecrypt RestoreStage = "decrypt"
	RestoreStageArchive RestoreStage = "archive"
	RestoreStageApply   RestoreStage = "apply"
)

type RestoreError struct {
	Stage RestoreStage
	Err   error
}

func (e *RestoreError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *RestoreError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type Barrier struct {
	mu sync.RWMutex
}

func NewBarrier() *Barrier {
	return &Barrier{}
}

func (b *Barrier) Lock() {
	if b != nil {
		b.mu.Lock()
	}
}

func (b *Barrier) Unlock() {
	if b != nil {
		b.mu.Unlock()
	}
}

func (b *Barrier) RLock() {
	if b != nil {
		b.mu.RLock()
	}
}

func (b *Barrier) RUnlock() {
	if b != nil {
		b.mu.RUnlock()
	}
}

func (b *Barrier) TryLock() bool {
	return b != nil && b.mu.TryLock()
}

func (b *Barrier) TryRLock() bool {
	return b != nil && b.mu.TryRLock()
}

type ServiceDeps struct {
	DB                      func() *sql.DB
	DBPath                  func() string
	ConfigPath              func() string
	KnownHostsWritePath     func() (string, error)
	EnsurePrivateDirForFile func(string) error
	EnsureSchema            func(*sql.DB) error
	DecodeEncryptionKey     func(string) ([]byte, error)
	CurrentEncryptionKey    func() []byte
	DecryptSecretWithKey    func(string, []byte) (string, error)
	EncryptSecretWithKey    func(string, []byte) (string, error)
	ResetRuntimeCaches      func()
	ReloadRuntimeState      func() error
	CurrentMaintenanceState func() MaintenanceState
	PersistMaintenanceState func(MaintenanceState) error
	Now                     func() time.Time
	Logf                    func(string, ...any)
}

type Service struct {
	deps ServiceDeps
}

func NewService(deps ServiceDeps) *Service {
	return &Service{deps: deps.withDefaults()}
}

func (deps ServiceDeps) withDefaults() ServiceDeps {
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Now().UTC() }
	}
	if deps.Logf == nil {
		deps.Logf = log.Printf
	}
	return deps
}

func sqliteStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func (s *Service) Status() StatusResponse {
	khPath, khExists := KnownHostsBackupPath(s.deps.KnownHostsWritePath, s.deps.DBPath)
	return StatusResponse{
		DBPath:           s.deps.DBPath(),
		ConfigPath:       s.deps.ConfigPath(),
		KnownHostsPath:   khPath,
		KnownHostsExists: khExists,
	}
}

func (s *Service) CreateDBSnapshot() ([]byte, error) {
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
	if err := ValidateSnapshotPath(tmpPath); err != nil {
		return nil, err
	}

	vacuumSQL := "VACUUM INTO " + sqliteStringLiteral(tmpPath)
	if _, err := s.deps.DB().Exec(vacuumSQL); err != nil {
		return nil, fmt.Errorf("snapshot database: %w", err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read db snapshot: %w", err)
	}
	return data, nil
}

func (s *Service) ExportArchive(ctx context.Context, req ExportRequest) (ExportResult, error) {
	_ = ctx
	req.Passphrase = strings.TrimSpace(req.Passphrase)
	if err := ValidatePassphrase(req.Passphrase); err != nil {
		return ExportResult{}, err
	}
	dbSnapshot := req.DBSnapshot
	if dbSnapshot == nil {
		var err error
		dbSnapshot, err = s.CreateDBSnapshot()
		if err != nil {
			return ExportResult{}, &ExportError{Stage: ExportStageSnapshot, Err: err}
		}
	}
	configData, err := os.ReadFile(s.deps.ConfigPath())
	if err != nil {
		return ExportResult{}, &ExportError{Stage: ExportStageConfig, Err: err}
	}

	files := map[string][]byte{
		"servers.db":  dbSnapshot,
		"config.json": configData,
	}
	includeKnownHosts := true
	if req.IncludeKnownHosts != nil {
		includeKnownHosts = *req.IncludeKnownHosts
	}
	knownHostsIncluded := false
	if includeKnownHosts {
		if path, exists := KnownHostsBackupPath(s.deps.KnownHostsWritePath, s.deps.DBPath); exists {
			if data, readErr := os.ReadFile(path); readErr == nil {
				files["known_hosts"] = data
				knownHostsIncluded = true
			}
		}
	}
	tarGz, err := BuildTarGz(files)
	if err != nil {
		return ExportResult{}, &ExportError{Stage: ExportStageArchive, Err: err}
	}
	encrypted, err := EncryptPayload(tarGz, req.Passphrase)
	if err != nil {
		return ExportResult{}, &ExportError{Stage: ExportStageEncrypt, Err: err}
	}
	return ExportResult{Bytes: encrypted, KnownHostsIncluded: knownHostsIncluded}, nil
}

func (s *Service) RestoreArchive(ctx context.Context, encrypted []byte, passphrase string) (RestoreResult, error) {
	return s.RestoreArchiveWithOptions(ctx, encrypted, passphrase, RestoreOptions{})
}

func (s *Service) RestoreArchiveWithOptions(ctx context.Context, encrypted []byte, passphrase string, opts RestoreOptions) (RestoreResult, error) {
	passphrase = strings.TrimSpace(passphrase)
	if err := ValidatePassphrase(passphrase); err != nil {
		return RestoreResult{}, err
	}
	plain, err := DecryptPayload(encrypted, passphrase)
	if err != nil {
		return RestoreResult{}, &RestoreError{Stage: RestoreStageDecrypt, Err: err}
	}
	files, manifest, err := ExtractTarGz(plain)
	if err != nil {
		return RestoreResult{}, &RestoreError{Stage: RestoreStageArchive, Err: err}
	}
	if opts.BeforeApply != nil {
		opts.BeforeApply()
	}
	if err := s.ApplyFiles(ctx, files); err != nil {
		return RestoreResult{}, &RestoreError{Stage: RestoreStageApply, Err: err}
	}
	globalKeyPresent, err := s.HasPersistedGlobalKey()
	if err != nil {
		s.deps.Logf("backup restore: failed to read global key presence after restore: %v", err)
	}
	_, knownHostsRestored := files["known_hosts"]
	return RestoreResult{
		Manifest:            manifest,
		GlobalKeyPresent:    globalKeyPresent,
		KnownHostsRestored:  knownHostsRestored,
		SessionsInvalidated: true,
	}, nil
}

func ValidatePassphrase(passphrase string) error {
	if len(strings.TrimSpace(passphrase)) < MinPassphraseLength {
		return ErrInvalidPassphrase
	}
	return nil
}

func ValidateSnapshotPath(path string) error {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" || !filepath.IsAbs(cleanPath) {
		return errors.New("invalid backup snapshot path")
	}
	if strings.ContainsAny(cleanPath, "\r\n") {
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

func KnownHostsBackupPath(knownHostsWritePath func() (string, error), dbPath func() string) (string, bool) {
	if knownHostsWritePath != nil {
		if p, err := knownHostsWritePath(); err == nil {
			if st, statErr := os.Stat(p); statErr == nil && !st.IsDir() {
				return p, true
			}
		}
	}
	defaultPath := ""
	if dbPath != nil {
		defaultPath = filepath.Join(filepath.Dir(dbPath()), "known_hosts")
	}
	if st, err := os.Stat(defaultPath); err == nil && !st.IsDir() {
		return defaultPath, true
	}
	return defaultPath, false
}

func BuildTarGz(files map[string][]byte) ([]byte, error) {
	manifest := Manifest{
		Format:    FormatName,
		Version:   FormatVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Files:     make(map[string]ManifestFile, len(files)),
	}
	for name, data := range files {
		sum := sha256.Sum256(data)
		manifest.Files[name] = ManifestFile{
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

func EncryptPayload(plain []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, ScryptN, ScryptR, ScryptP, KeyLen)
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
	env := Envelope{
		Format:    FormatName,
		Version:   FormatVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		KDF: KDFSpec{
			Name:    "scrypt",
			N:       ScryptN,
			R:       ScryptR,
			P:       ScryptP,
			SaltB64: base64.StdEncoding.EncodeToString(salt),
		},
		Cipher: CipherSpec{
			Name:     "aes-256-gcm",
			NonceB64: base64.StdEncoding.EncodeToString(nonce),
		},
		PayloadB64: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.Marshal(env)
}

func DecryptPayload(encrypted []byte, passphrase string) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(encrypted, &env); err != nil {
		return nil, ErrMalformed
	}
	if env.Format != FormatName || env.Version != FormatVersion {
		return nil, ErrUnsupportedFormat
	}
	if env.KDF.Name != "scrypt" || env.Cipher.Name != "aes-256-gcm" {
		return nil, ErrUnsupportedFormat
	}
	if env.KDF.N <= 0 || env.KDF.R <= 0 || env.KDF.P <= 0 {
		return nil, ErrUnsupportedFormat
	}
	if env.KDF.N != ScryptN || env.KDF.R != ScryptR || env.KDF.P != ScryptP {
		return nil, ErrUnsupportedFormat
	}
	salt, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.KDF.SaltB64))
	if err != nil || len(salt) == 0 {
		return nil, ErrMalformed
	}
	nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.Cipher.NonceB64))
	if err != nil || len(nonce) != 12 {
		return nil, ErrMalformed
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.PayloadB64))
	if err != nil || len(ciphertext) == 0 {
		return nil, ErrMalformed
	}
	key, err := scrypt.Key([]byte(passphrase), salt, ScryptN, ScryptR, ScryptP, KeyLen)
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

func ExtractTarGz(payload []byte) (map[string][]byte, Manifest, error) {
	return ExtractTarGzWithLimits(payload, MaxUploadBytes, MaxExtractedBytes)
}

func ExtractTarGzWithLimits(payload []byte, maxFileBytes, maxTotalBytes int64) (map[string][]byte, Manifest, error) {
	files := make(map[string][]byte)
	var totalExtracted int64
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, Manifest{}, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, Manifest{}, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size < 0 || hdr.Size > maxFileBytes {
			return nil, Manifest{}, fmt.Errorf("%w: backup entry %q is too large", ErrMalformed, hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFileBytes+1))
		if err != nil {
			return nil, Manifest{}, err
		}
		if int64(len(data)) > maxFileBytes {
			return nil, Manifest{}, fmt.Errorf("%w: backup entry %q is too large", ErrMalformed, hdr.Name)
		}
		if totalExtracted+int64(len(data)) > maxTotalBytes {
			return nil, Manifest{}, fmt.Errorf("%w: backup payload is too large", ErrMalformed)
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
		return nil, Manifest{}, ErrMalformed
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, Manifest{}, ErrMalformed
	}
	if manifest.Format != FormatName || manifest.Version != FormatVersion {
		return nil, Manifest{}, ErrUnsupportedFormat
	}
	if manifest.Files == nil {
		return nil, Manifest{}, ErrMalformed
	}
	for _, name := range []string{"servers.db", "config.json"} {
		if _, ok := files[name]; !ok {
			return nil, Manifest{}, fmt.Errorf("%w: %s", ErrMissingFile, name)
		}
		if _, ok := manifest.Files[name]; !ok {
			return nil, Manifest{}, fmt.Errorf("%w: %s", ErrMissingFile, name)
		}
	}
	if _, ok := files["known_hosts"]; ok {
		if _, ok := manifest.Files["known_hosts"]; !ok {
			return nil, Manifest{}, fmt.Errorf("%w: known_hosts", ErrMissingFile)
		}
	}
	for name, meta := range manifest.Files {
		if name != "servers.db" && name != "config.json" && name != "known_hosts" {
			return nil, Manifest{}, fmt.Errorf("%w: unexpected file %s", ErrMalformed, name)
		}
		data, exists := files[name]
		if !exists {
			return nil, Manifest{}, fmt.Errorf("%w: %s", ErrMissingFile, name)
		}
		if int64(len(data)) != meta.Size {
			return nil, Manifest{}, fmt.Errorf("checksum size mismatch for %s", name)
		}
		sum := sha256.Sum256(data)
		if !strings.EqualFold(meta.SHA256, hex.EncodeToString(sum[:])) {
			return nil, Manifest{}, fmt.Errorf("checksum mismatch for %s", name)
		}
	}
	return files, manifest, nil
}

func WriteAtomicFile(path string, data []byte, mode os.FileMode, ensurePrivateDirForFile func(string) error) error {
	if ensurePrivateDirForFile != nil {
		if err := ensurePrivateDirForFile(path); err != nil {
			return err
		}
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

func (s *Service) PersistActiveMaintenanceStateForRestore() error {
	state := s.deps.CurrentMaintenanceState()
	if !state.Active {
		return nil
	}
	if err := s.deps.PersistMaintenanceState(state); err != nil {
		return fmt.Errorf("persist active maintenance marker in restored database: %w", err)
	}
	return nil
}

func SnapshotExistingFiles(paths []string) (map[string]RestoreSnapshot, error) {
	out := make(map[string]RestoreSnapshot, len(paths))
	for _, p := range paths {
		st := RestoreSnapshot{Path: p, Exists: false}
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

func RestoreSnapshots(snaps map[string]RestoreSnapshot, ensurePrivateDirForFile func(string) error) error {
	for _, snap := range snaps {
		if snap.Exists {
			if err := WriteAtomicFile(snap.Path, snap.Data, 0600, ensurePrivateDirForFile); err != nil {
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

func SQLiteSidecarPaths(path string) []string {
	return []string{path + "-wal", path + "-shm"}
}

func RemoveSQLiteSidecars(path string) error {
	for _, sidecar := range SQLiteSidecarPaths(path) {
		if err := os.Remove(sidecar); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func requireRestoredDatabaseTables(ctx context.Context, db *sql.DB, names ...string) error {
	for _, name := range names {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = ?", name).Scan(&count); err != nil {
			return fmt.Errorf("inspect restored database table %s: %w", name, err)
		}
		if count == 0 {
			return fmt.Errorf("restored database is missing required table %s", name)
		}
	}
	return nil
}

func (s *Service) ValidateConfigData(data []byte) ([]byte, error) {
	var cfg map[string]string
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse restored config: %w", err)
	}
	key, err := s.deps.DecodeEncryptionKey(cfg["encryption_key"])
	if err != nil {
		return nil, fmt.Errorf("invalid restored encryption_key: %w", err)
	}
	return key, nil
}

func (s *Service) ValidateDatabaseData(ctx context.Context, data []byte, encryptionKey []byte) error {
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
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return fmt.Errorf("set restored database busy_timeout: %w", err)
	}
	if err := requireRestoredDatabaseTables(ctx, db, "servers"); err != nil {
		return err
	}
	if err := s.deps.EnsureSchema(db); err != nil {
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
		if _, err := s.deps.DecryptSecretWithKey(passEnc, encryptionKey); err != nil {
			return fmt.Errorf("decrypt restored password for %s: %w", name, err)
		}
		if _, err := s.deps.DecryptSecretWithKey(keyEnc, encryptionKey); err != nil {
			return fmt.Errorf("decrypt restored SSH key for %s: %w", name, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read restored servers: %w", err)
	}

	var globalKeyEnc string
	err = db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", "global_ssh_key").Scan(&globalKeyEnc)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read restored global SSH key: %w", err)
	}
	if err == nil && strings.TrimSpace(globalKeyEnc) != "" {
		if _, err := s.deps.DecryptSecretWithKey(globalKeyEnc, encryptionKey); err != nil {
			return fmt.Errorf("decrypt restored global SSH key: %w", err)
		}
	}
	return nil
}

func (s *Service) ReencryptDatabaseData(ctx context.Context, data []byte, fromKey, toKey []byte) ([]byte, error) {
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
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return nil, fmt.Errorf("set restored database rewrap busy_timeout: %w", err)
	}
	if err := requireRestoredDatabaseTables(ctx, db, "servers"); err != nil {
		return nil, err
	}
	if err := s.deps.EnsureSchema(db); err != nil {
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
		pass, err := s.deps.DecryptSecretWithKey(row.passEnc, fromKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt restored password for %s during rewrap: %w", row.name, err)
		}
		passEnc, err := s.deps.EncryptSecretWithKey(pass, toKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt restored password for %s during rewrap: %w", row.name, err)
		}
		key, err := s.deps.DecryptSecretWithKey(row.keyEnc, fromKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt restored SSH key for %s during rewrap: %w", row.name, err)
		}
		keyEnc, err := s.deps.EncryptSecretWithKey(key, toKey)
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
	err = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", "global_ssh_key").Scan(&globalKeyEnc)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read restored global SSH key for rewrap: %w", err)
	}
	if err == nil && strings.TrimSpace(globalKeyEnc) != "" {
		globalKey, err := s.deps.DecryptSecretWithKey(globalKeyEnc, fromKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt restored global SSH key during rewrap: %w", err)
		}
		rewrappedGlobalKey, err := s.deps.EncryptSecretWithKey(globalKey, toKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt restored global SSH key during rewrap: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE settings SET value = ? WHERE key = ?", rewrappedGlobalKey, "global_ssh_key"); err != nil {
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

func (s *Service) PrepareRuntimeFiles(ctx context.Context, files map[string][]byte) (map[string][]byte, error) {
	backupKey, err := s.ValidateConfigData(files["config.json"])
	if err != nil {
		return nil, err
	}
	if err := s.ValidateDatabaseData(ctx, files["servers.db"], backupKey); err != nil {
		return nil, err
	}
	rewrappedDB, err := s.ReencryptDatabaseData(ctx, files["servers.db"], backupKey, s.deps.CurrentEncryptionKey())
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

func (s *Service) ApplyFiles(ctx context.Context, files map[string][]byte) error {
	dbTarget := s.deps.DBPath()
	knownHostsTarget := filepath.Join(filepath.Dir(s.deps.DBPath()), "known_hosts")
	if p, err := s.deps.KnownHostsWritePath(); err == nil && strings.TrimSpace(p) != "" {
		knownHostsTarget = p
	}
	files, err := s.PrepareRuntimeFiles(ctx, files)
	if err != nil {
		return err
	}

	targets := []string{dbTarget}
	targets = append(targets, SQLiteSidecarPaths(dbTarget)...)
	if _, ok := files["known_hosts"]; ok {
		targets = append(targets, knownHostsTarget)
	}

	snaps, err := SnapshotExistingFiles(targets)
	if err != nil {
		return err
	}

	s.deps.ResetRuntimeCaches()
	rollback := func(cause error) error {
		errs := []error{cause}
		if restoreErr := RestoreSnapshots(snaps, s.deps.EnsurePrivateDirForFile); restoreErr != nil {
			errs = append(errs, fmt.Errorf("rollback restore snapshots: %w", restoreErr))
		}
		s.deps.ResetRuntimeCaches()
		if reloadErr := s.deps.ReloadRuntimeState(); reloadErr != nil {
			errs = append(errs, fmt.Errorf("rollback reload runtime state after reset: %w", reloadErr))
		}
		return errors.Join(errs...)
	}

	if err := RemoveSQLiteSidecars(dbTarget); err != nil {
		return rollback(err)
	}
	if err := WriteAtomicFile(dbTarget, files["servers.db"], 0600, s.deps.EnsurePrivateDirForFile); err != nil {
		return rollback(err)
	}
	if err := RemoveSQLiteSidecars(dbTarget); err != nil {
		return rollback(err)
	}
	if khData, ok := files["known_hosts"]; ok {
		if err := WriteAtomicFile(knownHostsTarget, khData, 0600, s.deps.EnsurePrivateDirForFile); err != nil {
			return rollback(err)
		}
	}
	if err := s.PersistActiveMaintenanceStateForRestore(); err != nil {
		return rollback(err)
	}
	if err := s.deps.ReloadRuntimeState(); err != nil {
		return rollback(err)
	}
	if err := s.ClearPersistedSessions(); err != nil {
		return rollback(err)
	}
	return nil
}

func (s *Service) ClearPersistedSessions() error {
	if _, err := s.deps.DB().Exec("DELETE FROM sessions"); err != nil {
		return fmt.Errorf("clear sessions: %w", err)
	}
	return nil
}

func (s *Service) HasPersistedGlobalKey() (bool, error) {
	var enc string
	err := s.deps.DB().QueryRow("SELECT value FROM settings WHERE key = ?", "global_ssh_key").Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(enc) != "", nil
}

func ReadUploadedFile(file *multipart.FileHeader) ([]byte, error) {
	if file == nil {
		return nil, errors.New("missing backup file")
	}
	if file.Size > MaxUploadBytes {
		return nil, fmt.Errorf("backup file too large (max %d bytes)", MaxUploadBytes)
	}
	src, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer src.Close()
	data, err := io.ReadAll(io.LimitReader(src, MaxUploadBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxUploadBytes {
		return nil, fmt.Errorf("backup file too large (max %d bytes)", MaxUploadBytes)
	}
	if len(data) == 0 {
		return nil, errors.New("empty backup file")
	}
	return data, nil
}
