package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"

	internalbackup "debian-updater/internal/backup"

	"github.com/gin-gonic/gin"
)

const (
	backupFileExtension         = internalbackup.FileExtension
	backupFormatName            = internalbackup.FormatName
	backupFormatVersion         = internalbackup.FormatVersion
	backupMaxUploadBytes        = internalbackup.MaxUploadBytes
	backupMaxExtractedBytes     = internalbackup.MaxExtractedBytes
	backupMaxExportRequestBytes = internalbackup.MaxExportRequestBytes
	backupMinPassphraseLength   = internalbackup.MinPassphraseLength
	backupScryptN               = internalbackup.ScryptN
	backupScryptR               = internalbackup.ScryptR
	backupScryptP               = internalbackup.ScryptP
	backupKeyLen                = internalbackup.KeyLen
)

type BackupService = internalbackup.Service
type BackupBarrier = internalbackup.Barrier
type backupExportRequest = internalbackup.ExportRequest
type backupManifest = internalbackup.Manifest
type backupManifestFile = internalbackup.ManifestFile

var (
	backupRestoreBarrier = internalbackup.NewBarrier()
	backupRestoreMu      = backupRestoreBarrier
	backupService        = NewBackupService()
)

func NewBackupService() *BackupService {
	return internalbackup.NewService(backupServiceDeps())
}

func backupServiceDeps() internalbackup.ServiceDeps {
	return internalbackup.ServiceDeps{
		DB:                      getDB,
		DBPath:                  dbPath,
		ConfigPath:              configPath,
		KnownHostsWritePath:     knownHostsWritePath,
		EnsurePrivateDirForFile: ensurePrivateDirForFile,
		EnsureSchema:            ensureSchema,
		DecodeEncryptionKey:     decodeEncryptionKeyValue,
		CurrentEncryptionKey:    getEncryptionKey,
		DecryptSecretWithKey:    decryptSecretWithKey,
		EncryptSecretWithKey:    encryptSecretWithKey,
		ResetRuntimeCaches:      resetRuntimeCaches,
		ReloadRuntimeState:      reloadRuntimeState,
		CurrentMaintenanceState: func() internalbackup.MaintenanceState {
			return internalbackup.MaintenanceState(currentMaintenanceState())
		},
		PersistMaintenanceState: func(state internalbackup.MaintenanceState) error {
			return persistMaintenanceState(MaintenanceState(state))
		},
		Now:  func() time.Time { return time.Now().UTC() },
		Logf: log.Printf,
	}
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
	return internalbackup.ValidatePassphrase(passphrase)
}

func createDBBackupSnapshot() ([]byte, error) {
	return backupService.CreateDBSnapshot()
}

func buildBackupTarGz(files map[string][]byte) ([]byte, error) {
	return internalbackup.BuildTarGz(files)
}

func encryptBackupPayload(plain []byte, passphrase string) ([]byte, error) {
	return internalbackup.EncryptPayload(plain, passphrase)
}

func decryptBackupPayload(encrypted []byte, passphrase string) ([]byte, error) {
	return internalbackup.DecryptPayload(encrypted, passphrase)
}

func extractBackupTarGz(payload []byte) (map[string][]byte, backupManifest, error) {
	return internalbackup.ExtractTarGz(payload)
}

func extractBackupTarGzWithLimits(payload []byte, maxFileBytes, maxTotalBytes int64) (map[string][]byte, backupManifest, error) {
	return internalbackup.ExtractTarGzWithLimits(payload, maxFileBytes, maxTotalBytes)
}

func persistActiveMaintenanceStateForRestore() error {
	return backupService.PersistActiveMaintenanceStateForRestore()
}

func sqliteSidecarPaths(path string) []string {
	return internalbackup.SQLiteSidecarPaths(path)
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

func applyBackupFiles(ctx context.Context, files map[string][]byte) error {
	return backupService.ApplyFiles(ctx, files)
}

//lint:ignore U1000 compatibility adapter retained for transitional route call sites.
func handleBackupStatus(c *gin.Context) {
	handleBackupStatusWithService(c, backupService)
}

func handleBackupStatusWithService(c *gin.Context, service *BackupService) {
	if service == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "backup service unavailable"})
		return
	}
	c.JSON(http.StatusOK, service.Status())
}

//lint:ignore U1000 compatibility adapter retained for transitional route call sites.
func handleBackupExport(c *gin.Context) {
	handleBackupExportWithService(c, backupService)
}

func handleBackupExportWithService(c *gin.Context, service *BackupService) {
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

	dbSnapshot, err := service.CreateDBSnapshot()
	if err != nil {
		audit(c, "backup.export", "backup", "state", "failure", "Failed to snapshot database", map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to snapshot database"})
		return
	}
	req.DBSnapshot = dbSnapshot

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

	phase := jobPhaseEncrypt
	summary := "Encrypting backup payload"
	_ = jm.UpdateJob(job.ID, JobUpdate{Phase: &phase, Summary: &summary})
	result, err := service.ExportArchive(c.Request.Context(), req)
	if err != nil {
		status := jobStatusFailed
		summary := "Failed to build backup payload"
		errorClass := "archive"
		publicError := "failed to build backup"
		auditMessage := "Failed to build backup payload"
		var exportErr *internalbackup.ExportError
		if errors.As(err, &exportErr) {
			switch exportErr.Stage {
			case internalbackup.ExportStageSnapshot:
				summary = "Failed to snapshot database"
				errorClass = "snapshot"
				publicError = "failed to snapshot database"
				auditMessage = "Failed to snapshot database"
			case internalbackup.ExportStageConfig:
				summary = "Failed to read config"
				errorClass = "config"
				publicError = "failed to read config"
				auditMessage = "Failed to read config"
			case internalbackup.ExportStageEncrypt:
				summary = "Failed to encrypt backup payload"
				errorClass = "encrypt"
				publicError = "failed to encrypt backup"
				auditMessage = "Failed to encrypt backup"
			}
		}
		finishedAt := jobTimestampNow()
		_ = jm.UpdateJob(job.ID, JobUpdate{
			Status:     &status,
			Summary:    &summary,
			ErrorClass: &errorClass,
			FinishedAt: &finishedAt,
		})
		audit(c, "backup.export", "backup", "state", "failure", auditMessage, map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": publicError})
		return
	}

	status := jobStatusSucceeded
	phase = jobPhaseComplete
	summary = "Backup export completed"
	finishedAt := jobTimestampNow()
	meta := marshalJobJSON(map[string]any{
		"bytes":                len(result.Bytes),
		"known_hosts_included": result.KnownHostsIncluded,
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
	c.Data(http.StatusOK, "application/octet-stream", result.Bytes)
	audit(c, "backup.export", "backup", "state", "success", "Backup exported", map[string]any{"bytes": len(result.Bytes), "known_hosts_included": result.KnownHostsIncluded})
}

func readUploadedBackupFile(file *multipart.FileHeader) ([]byte, error) {
	return internalbackup.ReadUploadedFile(file)
}

//lint:ignore U1000 compatibility adapter retained for transitional route call sites.
func handleBackupRestore(c *gin.Context) {
	handleBackupRestoreWithService(c, backupService)
}

func handleBackupRestoreWithService(c *gin.Context, service *BackupService) {
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

	restoreCtx := context.Background()
	if c.Request != nil {
		restoreCtx = c.Request.Context()
	}
	result, err := service.RestoreArchiveWithOptions(restoreCtx, blob, passphrase, internalbackup.RestoreOptions{
		BeforeApply: func() {
			phase := jobPhaseApply
			summary := "Applying restored backup files"
			_ = jm.UpdateJob(job.ID, JobUpdate{Phase: &phase, Summary: &summary})
		},
	})
	if err != nil {
		var restoreErr *internalbackup.RestoreError
		stage := internalbackup.RestoreStageApply
		if errors.As(err, &restoreErr) {
			stage = restoreErr.Stage
		}
		switch stage {
		case internalbackup.RestoreStageDecrypt:
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
		case internalbackup.RestoreStageArchive:
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
		default:
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
	}
	jm = currentJobManager()
	if persistErr := persistMaintenanceState(currentMaintenanceState()); persistErr != nil {
		log.Printf("handleBackupRestore: failed to re-persist active maintenance state after restore: %v", persistErr)
	}

	audit(c, "backup.restore", "backup", "state", "success", "Backup restored", map[string]any{
		"manifest_files":       len(result.Manifest.Files),
		"global_key_present":   result.GlobalKeyPresent,
		"known_hosts_restored": result.KnownHostsRestored,
	})
	expireSessionCookie(c)
	status := jobStatusSucceeded
	phase := jobPhaseComplete
	summary := "Backup restore completed"
	finishedAt := jobTimestampNow()
	meta := marshalJobJSON(map[string]any{
		"manifest_files":       len(result.Manifest.Files),
		"global_key_present":   result.GlobalKeyPresent,
		"known_hosts_restored": result.KnownHostsRestored,
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
		"global_key_present":   result.GlobalKeyPresent,
		"known_hosts_restored": result.KnownHostsRestored,
	})
}
