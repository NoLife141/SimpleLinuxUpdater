package jobs

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	KindUpdate         = "update"
	KindAutoremove     = "autoremove"
	KindSudoersEnable  = "sudoers_enable"
	KindSudoersDisable = "sudoers_disable"
	KindCVEEnrichment  = "cve_enrichment"
	KindBackupExport   = "backup_export"
	KindBackupRestore  = "backup_restore"
	KindScheduledScan  = "scheduled_scan"

	StatusQueued          = "queued"
	StatusRunning         = "running"
	StatusWaitingApproval = "waiting_approval"
	StatusSucceeded       = "succeeded"
	StatusFailed          = "failed"
	StatusCancelled       = "cancelled"
	StatusInterrupted     = "interrupted"

	PhaseDial         = "dial"
	PhasePrechecks    = "prechecks"
	PhaseAptUpdate    = "apt_update"
	PhaseApprovalWait = "approval_wait"
	PhaseAptUpgrade   = "apt_upgrade"
	PhasePostchecks   = "postchecks"
	PhaseAutoremove   = "autoremove"
	PhaseApply        = "apply"
	PhaseSnapshot     = "snapshot"
	PhaseEncrypt      = "encrypt"
	PhaseDecrypt      = "decrypt"
	PhaseLookup       = "lookup"
	PhaseComplete     = "complete"

	TimestampLayout = "2006-01-02T15:04:05.000000000Z"
)

type Record struct {
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

type Update struct {
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

type CreateParams struct {
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

type Repository interface {
	Create(record Record) error
	Upsert(record Record) error
	UpdateWithCondition(id string, update Update, updatedAt string, condition string, conditionArgs ...any) (bool, error)
	Get(id string) (Record, error)
	FindLatestActiveByServerAndKind(serverName, kind string) (*Record, error)
	ListUnfinished() ([]Record, error)
	MarkUnfinishedInterrupted(now string) error
}

type SQLiteRepository struct {
	db *sql.DB
}

type ManagerOptions struct {
	MaintenanceActive     func() bool
	MaintenanceError      error
	Notify                func(string)
	SyncRuntime           func(Record)
	SyncInterruptedServer func([]string)
	Now                   func() time.Time
	NewID                 func() string
}

type Manager struct {
	repo Repository
	opts ManagerOptions
}

func NewSQLiteRepository(db *sql.DB) *SQLiteRepository {
	return &SQLiteRepository{db: db}
}

func NewManager(repo Repository, opts ManagerOptions) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewID == nil {
		opts.NewID = NewID
	}
	return &Manager{repo: repo, opts: opts}
}

func EnsureSchema(db *sql.DB) error {
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

func NewID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	return fmt.Sprintf("job-%d", time.Now().UTC().UnixNano())
}

func MarshalJSON(v any) string {
	if v == nil {
		return "{}"
	}
	blob, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(blob)
}

func FormatTimestamp(t time.Time) string {
	return t.UTC().Format(TimestampLayout)
}

func ActiveStatuses() []string {
	return []string{StatusQueued, StatusRunning, StatusWaitingApproval}
}

func (m *Manager) timestampNow() string {
	return FormatTimestamp(m.now())
}

func (m *Manager) now() time.Time {
	if m == nil || m.opts.Now == nil {
		return time.Now()
	}
	return m.opts.Now()
}

func (m *Manager) CreateJob(params CreateParams) (Record, error) {
	if m == nil || m.repo == nil {
		return Record{}, errors.New("job manager is not initialized")
	}
	if m.opts.MaintenanceActive != nil && m.opts.MaintenanceActive() && params.Kind != KindBackupExport && params.Kind != KindBackupRestore {
		if m.opts.MaintenanceError != nil {
			return Record{}, m.opts.MaintenanceError
		}
		return Record{}, errors.New("maintenance mode active")
	}
	now := m.timestampNow()
	if strings.TrimSpace(params.Actor) == "" {
		params.Actor = "unknown"
	}
	if strings.TrimSpace(params.Status) == "" {
		params.Status = StatusQueued
	}
	if strings.TrimSpace(params.RetryPolicyJSON) == "" {
		params.RetryPolicyJSON = "{}"
	}
	if strings.TrimSpace(params.MetaJSON) == "" {
		params.MetaJSON = "{}"
	}
	record := Record{
		ID:              m.opts.NewID(),
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
	if err := m.repo.Create(record); err != nil {
		return Record{}, err
	}
	m.notify("job.create")
	return record, nil
}

func (m *Manager) UpsertJobRecord(record Record) error {
	if m == nil || m.repo == nil {
		return errors.New("job manager is not initialized")
	}
	now := m.timestampNow()
	if strings.TrimSpace(record.ID) == "" {
		record.ID = m.opts.NewID()
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
	if err := m.repo.Upsert(record); err != nil {
		return err
	}
	m.syncRuntime(record.ID)
	m.notify("job.upsert")
	return nil
}

func (m *Manager) UpdateActiveJob(id string, update Update) (bool, error) {
	active := ActiveStatuses()
	return m.updateJobWithCondition(
		id,
		update,
		true,
		"status IN (?, ?, ?)",
		active[0],
		active[1],
		active[2],
	)
}

func (m *Manager) UpdateJob(id string, update Update) error {
	return m.updateJob(id, update, true)
}

func (m *Manager) UpdateJobWithoutRuntimeSync(id string, update Update) error {
	return m.updateJob(id, update, false)
}

func (m *Manager) GetJob(id string) (Record, error) {
	if m == nil || m.repo == nil {
		return Record{}, errors.New("job manager is not initialized")
	}
	return m.repo.Get(id)
}

func (m *Manager) FindLatestActiveJobByServerAndKind(serverName, kind string) (*Record, error) {
	if m == nil || m.repo == nil {
		return nil, errors.New("job manager is not initialized")
	}
	serverName = strings.TrimSpace(serverName)
	kind = strings.TrimSpace(kind)
	if serverName == "" || kind == "" {
		return nil, sql.ErrNoRows
	}
	return m.repo.FindLatestActiveByServerAndKind(serverName, kind)
}

func (m *Manager) MarkUnfinishedJobsInterrupted() error {
	if m == nil || m.repo == nil {
		return nil
	}
	unfinished, err := m.repo.ListUnfinished()
	if err != nil {
		return err
	}
	if len(unfinished) == 0 {
		return nil
	}
	now := m.timestampNow()
	if err := m.repo.MarkUnfinishedInterrupted(now); err != nil {
		return err
	}
	affected := make([]string, 0, len(unfinished))
	seen := make(map[string]struct{}, len(unfinished))
	for _, record := range unfinished {
		serverName := strings.TrimSpace(record.ServerName)
		if serverName == "" {
			continue
		}
		if _, ok := seen[serverName]; ok {
			continue
		}
		seen[serverName] = struct{}{}
		affected = append(affected, serverName)
	}
	if len(affected) > 0 && m.opts.SyncInterruptedServer != nil {
		m.opts.SyncInterruptedServer(affected)
	}
	return nil
}

func (m *Manager) updateJob(id string, update Update, syncRuntime bool) error {
	_, err := m.updateJobWithCondition(id, update, syncRuntime, "")
	return err
}

func (m *Manager) updateJobWithCondition(id string, update Update, syncRuntime bool, condition string, conditionArgs ...any) (bool, error) {
	if m == nil || m.repo == nil || strings.TrimSpace(id) == "" {
		return false, nil
	}
	updated, err := m.repo.UpdateWithCondition(id, update, m.timestampNow(), condition, conditionArgs...)
	if err != nil {
		return false, err
	}
	if updated && syncRuntime {
		m.syncRuntime(id)
	}
	if updated {
		m.notify("job.update")
	}
	return updated, nil
}

func (m *Manager) syncRuntime(id string) {
	if m == nil || m.opts.SyncRuntime == nil {
		return
	}
	record, err := m.GetJob(id)
	if err != nil {
		return
	}
	m.opts.SyncRuntime(record)
}

func (m *Manager) notify(reason string) {
	if m != nil && m.opts.Notify != nil {
		m.opts.Notify(reason)
	}
}

func (r *SQLiteRepository) Create(record Record) error {
	if r == nil || r.db == nil {
		return errors.New("job repository is not initialized")
	}
	_, err := r.db.Exec(`
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
	)
	return err
}

func (r *SQLiteRepository) Upsert(record Record) error {
	if r == nil || r.db == nil {
		return errors.New("job repository is not initialized")
	}
	_, err := r.db.Exec(`
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
	return err
}

func (r *SQLiteRepository) UpdateWithCondition(id string, update Update, updatedAt string, condition string, conditionArgs ...any) (bool, error) {
	if r == nil || r.db == nil || strings.TrimSpace(id) == "" {
		return false, nil
	}
	setClauses := []string{"updated_at = ?"}
	args := []any{updatedAt}
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
	query := "UPDATE jobs SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
	if strings.TrimSpace(condition) != "" {
		query += " AND " + condition
		args = append(args, conditionArgs...)
	}
	result, err := r.db.Exec(query, args...)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		rowsAffected = 1
	}
	return rowsAffected > 0, nil
}

func (r *SQLiteRepository) Get(id string) (Record, error) {
	if r == nil || r.db == nil {
		return Record{}, errors.New("job repository is not initialized")
	}
	var record Record
	err := r.db.QueryRow(`
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

func (r *SQLiteRepository) FindLatestActiveByServerAndKind(serverName, kind string) (*Record, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("job repository is not initialized")
	}
	var record Record
	err := r.db.QueryRow(`
		SELECT id, kind, parent_job_id, server_name, actor, client_ip, status, phase, summary, logs_text,
		       error_class, retry_policy_json, meta_json, created_at, updated_at, started_at, finished_at
		  FROM jobs
		 WHERE server_name = ?
		   AND kind = ?
		   AND status IN (?, ?, ?)
		 ORDER BY created_at DESC
		 LIMIT 1
	`, serverName, kind, StatusQueued, StatusRunning, StatusWaitingApproval).Scan(
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

func (r *SQLiteRepository) ListUnfinished() ([]Record, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("job repository is not initialized")
	}
	rows, err := r.db.Query(`
		SELECT id, kind, parent_job_id, server_name, actor, client_ip, status, phase, summary, logs_text,
		       error_class, retry_policy_json, meta_json, created_at, updated_at, started_at, finished_at
		  FROM jobs
		 WHERE status IN (?, ?, ?)
	`, StatusQueued, StatusRunning, StatusWaitingApproval)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		var record Record
		if err := rows.Scan(
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
		); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (r *SQLiteRepository) MarkUnfinishedInterrupted(now string) error {
	if r == nil || r.db == nil {
		return errors.New("job repository is not initialized")
	}
	_, err := r.db.Exec(`
		UPDATE jobs
		   SET status = ?, summary = ?, finished_at = ?, updated_at = ?
		 WHERE status IN (?, ?, ?)
	`, StatusInterrupted, "Interrupted during restart recovery", now, now, StatusQueued, StatusRunning, StatusWaitingApproval)
	return err
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
