package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	jobKindUpdate         = "update"
	jobKindAutoremove     = "autoremove"
	jobKindSudoersEnable  = "sudoers_enable"
	jobKindSudoersDisable = "sudoers_disable"
	jobKindCVEEnrichment  = "cve_enrichment"
	jobKindBackupExport   = "backup_export"
	jobKindBackupRestore  = "backup_restore"

	jobStatusQueued          = "queued"
	jobStatusRunning         = "running"
	jobStatusWaitingApproval = "waiting_approval"
	jobStatusSucceeded       = "succeeded"
	jobStatusFailed          = "failed"
	jobStatusCancelled       = "cancelled"
	jobStatusInterrupted     = "interrupted"

	jobPhaseDial         = "dial"
	jobPhasePrechecks    = "prechecks"
	jobPhaseAptUpdate    = "apt_update"
	jobPhaseApprovalWait = "approval_wait"
	jobPhaseAptUpgrade   = "apt_upgrade"
	jobPhasePostchecks   = "postchecks"
	jobPhaseAutoremove   = "autoremove"
	jobPhaseApply        = "apply"
	jobPhaseSnapshot     = "snapshot"
	jobPhaseEncrypt      = "encrypt"
	jobPhaseDecrypt      = "decrypt"
	jobPhaseLookup       = "lookup"
	jobPhaseComplete     = "complete"

	jobTimestampLayout = "2006-01-02T15:04:05.000000000Z"
)

type JobRecord struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	ParentJobID     string `json:"parent_job_id"`
	ServerName      string `json:"server_name"`
	Actor           string `json:"actor"`
	ClientIP        string `json:"client_ip"`
	Status          string `json:"status"`
	Phase           string `json:"phase"`
	Summary         string `json:"summary"`
	LogsText        string `json:"logs_text"`
	ErrorClass      string `json:"error_class"`
	RetryPolicyJSON string `json:"retry_policy_json"`
	MetaJSON        string `json:"meta_json"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
}

type JobUpdate struct {
	Status     *string
	Phase      *string
	Summary    *string
	LogsText   *string
	AppendLog  string
	ErrorClass *string
	MetaJSON   *string
	StartedAt  *string
	FinishedAt *string
}

type JobManager struct {
	db *sql.DB
}

type JobCreateParams struct {
	Kind            string
	ParentJobID     string
	ServerName      string
	Actor           string
	ClientIP        string
	Status          string
	Phase           string
	Summary         string
	LogsText        string
	ErrorClass      string
	RetryPolicyJSON string
	MetaJSON        string
	StartedAt       string
	FinishedAt      string
}

var (
	jobManagerMu sync.RWMutex
	jobManager   *JobManager
)

func currentJobManager() *JobManager {
	jobManagerMu.RLock()
	defer jobManagerMu.RUnlock()
	return jobManager
}

func setCurrentJobManager(jm *JobManager) {
	jobManagerMu.Lock()
	defer jobManagerMu.Unlock()
	jobManager = jm
}

func newJobManager(db *sql.DB) *JobManager {
	return &JobManager{db: db}
}

func initializeJobManager() error {
	jm := newJobManager(getDB())
	if err := jm.MarkUnfinishedJobsInterrupted(); err != nil {
		return err
	}
	setCurrentJobManager(jm)
	return nil
}

func ensureJobSchema(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS jobs (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			parent_job_id TEXT NOT NULL DEFAULT '',
			server_name TEXT NOT NULL DEFAULT '',
			actor TEXT NOT NULL,
			client_ip TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			phase TEXT NOT NULL DEFAULT '',
			summary TEXT NOT NULL DEFAULT '',
			logs_text TEXT NOT NULL DEFAULT '',
			error_class TEXT NOT NULL DEFAULT '',
			retry_policy_json TEXT NOT NULL DEFAULT '{}',
			meta_json TEXT NOT NULL DEFAULT '{}',
			-- Fixed-width UTC timestamps keep TEXT ordering chronological.
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			started_at TEXT NOT NULL DEFAULT '',
			finished_at TEXT NOT NULL DEFAULT ''
		)
	`); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_jobs_server_created_at ON jobs (server_name, created_at DESC)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_jobs_status_created_at ON jobs (status, created_at DESC)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_jobs_kind_created_at ON jobs (kind, created_at DESC)"); err != nil {
		return err
	}
	return nil
}

func newJobID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	return fmt.Sprintf("job-%d", time.Now().UTC().UnixNano())
}

func marshalJobJSON(v any) string {
	if v == nil {
		return "{}"
	}
	blob, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(blob)
}

func formatJobTimestamp(t time.Time) string {
	return t.UTC().Format(jobTimestampLayout)
}

func jobTimestampNow() string {
	return formatJobTimestamp(time.Now())
}

func (jm *JobManager) CreateJob(params JobCreateParams) (JobRecord, error) {
	if jm == nil || jm.db == nil {
		return JobRecord{}, errors.New("job manager is not initialized")
	}
	if currentMaintenanceState().Active && params.Kind != jobKindBackupExport && params.Kind != jobKindBackupRestore {
		return JobRecord{}, errMaintenanceModeActive
	}
	now := jobTimestampNow()
	if strings.TrimSpace(params.Actor) == "" {
		params.Actor = "unknown"
	}
	if strings.TrimSpace(params.Status) == "" {
		params.Status = jobStatusQueued
	}
	if strings.TrimSpace(params.RetryPolicyJSON) == "" {
		params.RetryPolicyJSON = "{}"
	}
	if strings.TrimSpace(params.MetaJSON) == "" {
		params.MetaJSON = "{}"
	}
	record := JobRecord{
		ID:              newJobID(),
		Kind:            strings.TrimSpace(params.Kind),
		ParentJobID:     strings.TrimSpace(params.ParentJobID),
		ServerName:      strings.TrimSpace(params.ServerName),
		Actor:           strings.TrimSpace(params.Actor),
		ClientIP:        truncateString(strings.TrimSpace(params.ClientIP), 128),
		Status:          strings.TrimSpace(params.Status),
		Phase:           strings.TrimSpace(params.Phase),
		Summary:         strings.TrimSpace(params.Summary),
		LogsText:        params.LogsText,
		ErrorClass:      strings.TrimSpace(params.ErrorClass),
		RetryPolicyJSON: params.RetryPolicyJSON,
		MetaJSON:        params.MetaJSON,
		CreatedAt:       now,
		UpdatedAt:       now,
		StartedAt:       strings.TrimSpace(params.StartedAt),
		FinishedAt:      strings.TrimSpace(params.FinishedAt),
	}
	if _, err := jm.db.Exec(`
		INSERT INTO jobs (
			id, kind, parent_job_id, server_name, actor, client_ip, status, phase, summary, logs_text,
			error_class, retry_policy_json, meta_json, created_at, updated_at, started_at, finished_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.ID,
		record.Kind,
		record.ParentJobID,
		record.ServerName,
		record.Actor,
		record.ClientIP,
		record.Status,
		record.Phase,
		record.Summary,
		record.LogsText,
		record.ErrorClass,
		record.RetryPolicyJSON,
		record.MetaJSON,
		record.CreatedAt,
		record.UpdatedAt,
		record.StartedAt,
		record.FinishedAt,
	); err != nil {
		return JobRecord{}, err
	}
	return record, nil
}

func (jm *JobManager) UpsertJobRecord(record JobRecord) error {
	if jm == nil || jm.db == nil {
		return errors.New("job manager is not initialized")
	}
	now := jobTimestampNow()
	if strings.TrimSpace(record.ID) == "" {
		record.ID = newJobID()
	}
	if strings.TrimSpace(record.CreatedAt) == "" {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	if strings.TrimSpace(record.Actor) == "" {
		record.Actor = "unknown"
	}
	if strings.TrimSpace(record.RetryPolicyJSON) == "" {
		record.RetryPolicyJSON = "{}"
	}
	if strings.TrimSpace(record.MetaJSON) == "" {
		record.MetaJSON = "{}"
	}
	_, err := jm.db.Exec(`
		INSERT INTO jobs (
			id, kind, parent_job_id, server_name, actor, client_ip, status, phase, summary, logs_text,
			error_class, retry_policy_json, meta_json, created_at, updated_at, started_at, finished_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			kind = excluded.kind,
			parent_job_id = excluded.parent_job_id,
			server_name = excluded.server_name,
			actor = excluded.actor,
			client_ip = excluded.client_ip,
			status = excluded.status,
			phase = excluded.phase,
			summary = excluded.summary,
			logs_text = excluded.logs_text,
			error_class = excluded.error_class,
			retry_policy_json = excluded.retry_policy_json,
			meta_json = excluded.meta_json,
			updated_at = excluded.updated_at,
			started_at = excluded.started_at,
			finished_at = excluded.finished_at
	`,
		record.ID,
		record.Kind,
		record.ParentJobID,
		record.ServerName,
		record.Actor,
		record.ClientIP,
		record.Status,
		record.Phase,
		record.Summary,
		record.LogsText,
		record.ErrorClass,
		record.RetryPolicyJSON,
		record.MetaJSON,
		record.CreatedAt,
		record.UpdatedAt,
		record.StartedAt,
		record.FinishedAt,
	)
	if err != nil {
		return err
	}
	jm.syncStatusMapFromJobID(record.ID)
	return nil
}

func (jm *JobManager) UpdateJob(id string, update JobUpdate) error {
	if jm == nil || jm.db == nil || strings.TrimSpace(id) == "" {
		return nil
	}
	now := jobTimestampNow()
	setClauses := []string{"updated_at = ?"}
	args := []any{now}
	if update.Status != nil {
		setClauses = append(setClauses, "status = ?")
		args = append(args, strings.TrimSpace(*update.Status))
	}
	if update.Phase != nil {
		setClauses = append(setClauses, "phase = ?")
		args = append(args, strings.TrimSpace(*update.Phase))
	}
	if update.Summary != nil {
		setClauses = append(setClauses, "summary = ?")
		args = append(args, strings.TrimSpace(*update.Summary))
	}
	if update.LogsText != nil {
		setClauses = append(setClauses, "logs_text = ?")
		args = append(args, *update.LogsText)
	}
	if update.AppendLog != "" {
		setClauses = append(setClauses, "logs_text = COALESCE(logs_text, '') || ?")
		args = append(args, update.AppendLog)
	}
	if update.ErrorClass != nil {
		setClauses = append(setClauses, "error_class = ?")
		args = append(args, strings.TrimSpace(*update.ErrorClass))
	}
	if update.MetaJSON != nil {
		setClauses = append(setClauses, "meta_json = ?")
		args = append(args, strings.TrimSpace(*update.MetaJSON))
	}
	if update.StartedAt != nil {
		setClauses = append(setClauses, "started_at = ?")
		args = append(args, strings.TrimSpace(*update.StartedAt))
	}
	if update.FinishedAt != nil {
		setClauses = append(setClauses, "finished_at = ?")
		args = append(args, strings.TrimSpace(*update.FinishedAt))
	}
	args = append(args, id)
	if _, err := jm.db.Exec("UPDATE jobs SET "+strings.Join(setClauses, ", ")+" WHERE id = ?", args...); err != nil {
		return err
	}
	jm.syncStatusMapFromJobID(id)
	return nil
}

func (jm *JobManager) GetJob(id string) (JobRecord, error) {
	if jm == nil || jm.db == nil {
		return JobRecord{}, errors.New("job manager is not initialized")
	}
	var record JobRecord
	err := jm.db.QueryRow(`
		SELECT id, kind, parent_job_id, server_name, actor, client_ip, status, phase, summary, logs_text,
		       error_class, retry_policy_json, meta_json, created_at, updated_at, started_at, finished_at
		  FROM jobs
		 WHERE id = ?
	`, id).Scan(
		&record.ID,
		&record.Kind,
		&record.ParentJobID,
		&record.ServerName,
		&record.Actor,
		&record.ClientIP,
		&record.Status,
		&record.Phase,
		&record.Summary,
		&record.LogsText,
		&record.ErrorClass,
		&record.RetryPolicyJSON,
		&record.MetaJSON,
		&record.CreatedAt,
		&record.UpdatedAt,
		&record.StartedAt,
		&record.FinishedAt,
	)
	return record, err
}

func (jm *JobManager) FindLatestActiveJobByServerAndKind(serverName, kind string) (*JobRecord, error) {
	if jm == nil || jm.db == nil {
		return nil, errors.New("job manager is not initialized")
	}
	serverName = strings.TrimSpace(serverName)
	kind = strings.TrimSpace(kind)
	if serverName == "" || kind == "" {
		return nil, sql.ErrNoRows
	}
	var record JobRecord
	err := jm.db.QueryRow(`
		SELECT id, kind, parent_job_id, server_name, actor, client_ip, status, phase, summary, logs_text,
		       error_class, retry_policy_json, meta_json, created_at, updated_at, started_at, finished_at
		  FROM jobs
		 WHERE server_name = ?
		   AND kind = ?
		   AND status IN (?, ?, ?)
		 ORDER BY created_at DESC
		 LIMIT 1
	`, serverName, kind, jobStatusQueued, jobStatusRunning, jobStatusWaitingApproval).Scan(
		&record.ID,
		&record.Kind,
		&record.ParentJobID,
		&record.ServerName,
		&record.Actor,
		&record.ClientIP,
		&record.Status,
		&record.Phase,
		&record.Summary,
		&record.LogsText,
		&record.ErrorClass,
		&record.RetryPolicyJSON,
		&record.MetaJSON,
		&record.CreatedAt,
		&record.UpdatedAt,
		&record.StartedAt,
		&record.FinishedAt,
	)
	if err == sql.ErrNoRows {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (jm *JobManager) MarkUnfinishedJobsInterrupted() error {
	if jm == nil || jm.db == nil {
		return nil
	}
	rows, err := jm.db.Query(`
		SELECT id, server_name
		  FROM jobs
		 WHERE status IN (?, ?, ?)
	`, jobStatusQueued, jobStatusRunning, jobStatusWaitingApproval)
	if err != nil {
		return err
	}
	defer rows.Close()

	var affectedJobIDs []string
	affectedServers := make(map[string]struct{})
	for rows.Next() {
		var id, serverName string
		if err := rows.Scan(&id, &serverName); err != nil {
			return err
		}
		affectedJobIDs = append(affectedJobIDs, id)
		if strings.TrimSpace(serverName) != "" {
			affectedServers[serverName] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(affectedJobIDs) == 0 {
		return nil
	}
	now := jobTimestampNow()
	if _, err := jm.db.Exec(`
		UPDATE jobs
		   SET status = ?, summary = ?, finished_at = ?, updated_at = ?
		 WHERE status IN (?, ?, ?)
	`, jobStatusInterrupted, "Interrupted during restart recovery", now, now, jobStatusQueued, jobStatusRunning, jobStatusWaitingApproval); err != nil {
		return err
	}

	mu.Lock()
	defer mu.Unlock()
	for serverName := range affectedServers {
		status := statusMap[serverName]
		if status == nil {
			continue
		}
		status.Status = "idle"
		status.ApprovalScope = ""
		status.Upgradable = nil
		status.PendingUpdates = nil
	}
	return nil
}

func (jm *JobManager) syncStatusMapFromJobID(id string) {
	record, err := jm.GetJob(id)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("job sync failed for %q: %v", id, err)
		}
		return
	}
	if strings.TrimSpace(record.ServerName) == "" {
		return
	}
	statusValue := runtimeStatusFromJob(record)
	if statusValue == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	status := statusMap[record.ServerName]
	if status == nil {
		return
	}
	status.Status = statusValue
	if record.LogsText != "" {
		status.Logs = record.LogsText
	}
	if record.Status == jobStatusInterrupted {
		status.ApprovalScope = ""
		status.Upgradable = nil
		status.PendingUpdates = nil
	}
}

func runtimeStatusFromJob(record JobRecord) string {
	switch record.Status {
	case jobStatusWaitingApproval:
		return "pending_approval"
	case jobStatusSucceeded:
		return "done"
	case jobStatusFailed:
		return "error"
	case jobStatusCancelled:
		return "cancelled"
	case jobStatusInterrupted:
		return "idle"
	}
	switch record.Kind {
	case jobKindUpdate:
		switch record.Phase {
		case jobPhaseApprovalWait:
			return "pending_approval"
		case jobPhaseAptUpgrade, jobPhasePostchecks, jobPhaseComplete:
			return "upgrading"
		default:
			return "updating"
		}
	case jobKindAutoremove:
		return "autoremove"
	case jobKindSudoersEnable, jobKindSudoersDisable:
		return "sudoers"
	default:
		return ""
	}
}

func startJobRunner(jobID string, run func()) {
	startTrackedActionRunner(func() {
		jm := currentJobManager()
		if jm != nil && strings.TrimSpace(jobID) != "" {
			now := jobTimestampNow()
			status := jobStatusRunning
			if err := jm.UpdateJob(jobID, JobUpdate{
				Status:    &status,
				StartedAt: &now,
			}); err != nil {
				log.Printf("failed to mark job %q running: %v", jobID, err)
			}
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("job runner panic for job %q: %v", jobID, recovered)
				if jm := currentJobManager(); jm != nil && strings.TrimSpace(jobID) != "" {
					status := jobStatusFailed
					summary := "Runner panicked"
					errorClass := "panic"
					finishedAt := jobTimestampNow()
					_ = jm.UpdateJob(jobID, JobUpdate{
						Status:     &status,
						Summary:    &summary,
						ErrorClass: &errorClass,
						FinishedAt: &finishedAt,
					})
				}
				panic(recovered)
			}
		}()
		run()
	})
}
