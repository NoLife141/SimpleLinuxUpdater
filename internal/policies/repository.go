package policies

import (
	"database/sql"
	"errors"
	"strings"

	"debian-updater/internal/servers"
)

type Repository interface {
	ListPolicies() ([]Policy, error)
	GetPolicy(id int64) (Policy, error)
	CreatePolicy(policy Policy) (Policy, error)
	UpdatePolicy(id int64, policy Policy) (Policy, error)
	DeletePolicy(id int64) error
	ListOverrides(policyID int64) ([]Override, error)
	LoadAllOverrides() (map[int64]map[string]bool, error)
	SetOverride(policyID int64, serverName string, disabled bool) (Override, error)
	RenameOverridesServerTx(tx *sql.Tx, oldServerName, newServerName string) error
	RenameTargetServersTx(tx *sql.Tx, oldServerName, newServerName string) error
	PruneOverridesForServersTx(tx *sql.Tx, activeServers []servers.Server) error
	CreateRun(run Run) (Run, bool, error)
	FindRun(policyID int64, serverName, scheduledForUTC string) (Run, error)
	GetRun(id int64) (Run, error)
	UpdateRun(id int64, update RunUpdate) error
	ListRuns(limit int) ([]Run, error)
	MarkInterruptedRuns() error
	LoadGlobalBlackouts() ([]BlackoutWindow, error)
	SaveGlobalBlackouts(windows []BlackoutWindow) ([]BlackoutWindow, error)
}

type SQLiteRepositoryDeps struct {
	DB          func() *sql.DB
	NowString   func() string
	MarshalJSON func(any) string
}

type SQLiteRepository struct {
	db          func() *sql.DB
	nowString   func() string
	marshalJSON func(any) string
}

func NewSQLiteRepository(deps SQLiteRepositoryDeps) *SQLiteRepository {
	repo := &SQLiteRepository{
		db:          deps.DB,
		nowString:   deps.NowString,
		marshalJSON: deps.MarshalJSON,
	}
	if repo.nowString == nil {
		repo.nowString = func() string { return "" }
	}
	if repo.marshalJSON == nil {
		repo.marshalJSON = marshalJSON
	}
	return repo
}

func (r *SQLiteRepository) database() *sql.DB {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db()
}

func (r *SQLiteRepository) now() string {
	if r == nil || r.nowString == nil {
		return ""
	}
	return r.nowString()
}

func (r *SQLiteRepository) json(v any) string {
	if r == nil || r.marshalJSON == nil {
		return marshalJSON(v)
	}
	return r.marshalJSON(v)
}

func EnsureSchema(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS update_policies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			target_tag TEXT NOT NULL,
			include_tags_json TEXT NOT NULL DEFAULT '[]',
			exclude_tags_json TEXT NOT NULL DEFAULT '[]',
			target_servers_json TEXT NOT NULL DEFAULT '[]',
			package_scope TEXT NOT NULL,
			execution_mode TEXT NOT NULL,
			cadence_kind TEXT NOT NULL,
			time_local TEXT NOT NULL,
			weekdays_json TEXT NOT NULL DEFAULT '[]',
			approval_timeout_minutes INTEGER NOT NULL DEFAULT 720,
			policy_blackouts_json TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)
	`); err != nil {
		return err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS update_policy_overrides (
			policy_id INTEGER NOT NULL,
			server_name TEXT NOT NULL,
			disabled INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (policy_id, server_name)
		)
	`); err != nil {
		return err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS update_policy_runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			policy_id INTEGER NOT NULL,
			policy_name TEXT NOT NULL DEFAULT '',
			server_name TEXT NOT NULL,
			scheduled_for_utc TEXT NOT NULL,
			execution_mode TEXT NOT NULL,
			package_scope TEXT NOT NULL,
			status TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			summary TEXT NOT NULL DEFAULT '',
			job_id TEXT NOT NULL DEFAULT '',
			result_json TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			started_at TEXT NOT NULL DEFAULT '',
			finished_at TEXT NOT NULL DEFAULT '',
			UNIQUE(policy_id, server_name, scheduled_for_utc)
		)
	`); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_update_policy_runs_scheduled_for ON update_policy_runs (scheduled_for_utc DESC)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_update_policy_runs_status ON update_policy_runs (status, scheduled_for_utc DESC)"); err != nil {
		return err
	}
	if err := ensureColumn(db, "include_tags_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := ensureColumn(db, "exclude_tags_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := ensureColumn(db, "target_servers_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	return nil
}

func ensureColumn(db *sql.DB, name, definition string) error {
	rows, err := db.Query("PRAGMA table_info(update_policies)")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var columnName, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &columnName, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if columnName == name {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE update_policies ADD COLUMN " + name + " " + definition)
	return err
}

func (r *SQLiteRepository) getSettingValue(key string) (string, error) {
	var value string
	err := r.database().QueryRow("SELECT value FROM settings WHERE key = ?", strings.TrimSpace(key)).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (r *SQLiteRepository) upsertSettingValue(key, value string) error {
	_, err := r.database().Exec(
		"INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		strings.TrimSpace(key),
		value,
	)
	return err
}

func (r *SQLiteRepository) LoadGlobalBlackouts() ([]BlackoutWindow, error) {
	raw, err := r.getSettingValue(GlobalBlackoutsSetting)
	if err != nil {
		return nil, err
	}
	return ParseBlackouts(raw)
}

func (r *SQLiteRepository) SaveGlobalBlackouts(windows []BlackoutWindow) ([]BlackoutWindow, error) {
	normalized, err := NormalizeBlackouts(windows)
	if err != nil {
		return nil, err
	}
	if err := r.upsertSettingValue(GlobalBlackoutsSetting, r.json(normalized)); err != nil {
		return nil, err
	}
	return normalized, nil
}

func (r *SQLiteRepository) ListPolicies() ([]Policy, error) {
	rows, err := r.database().Query(`
		SELECT id, name, enabled, target_tag, include_tags_json, exclude_tags_json, target_servers_json,
		       package_scope, execution_mode, cadence_kind, time_local,
		       weekdays_json, approval_timeout_minutes, policy_blackouts_json, created_at, updated_at
		  FROM update_policies
		 ORDER BY created_at ASC, id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := make([]Policy, 0)
	for rows.Next() {
		policy, scanErr := scanPolicyRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return policies, nil
}

func (r *SQLiteRepository) GetPolicy(id int64) (Policy, error) {
	row := r.database().QueryRow(`
		SELECT id, name, enabled, target_tag, include_tags_json, exclude_tags_json, target_servers_json,
		       package_scope, execution_mode, cadence_kind, time_local,
		       weekdays_json, approval_timeout_minutes, policy_blackouts_json, created_at, updated_at
		  FROM update_policies
		 WHERE id = ?
	`, id)
	return scanPolicyRow(row)
}

func (r *SQLiteRepository) CreatePolicy(policy Policy) (Policy, error) {
	now := r.now()
	result, err := r.database().Exec(`
		INSERT INTO update_policies (
			name, enabled, target_tag, include_tags_json, exclude_tags_json, target_servers_json,
			package_scope, execution_mode, cadence_kind, time_local,
			weekdays_json, approval_timeout_minutes, policy_blackouts_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		policy.Name,
		BoolToInt(policy.Enabled),
		policy.TargetTag,
		r.json(policy.IncludeTags),
		r.json(policy.ExcludeTags),
		r.json(policy.TargetServers),
		policy.PackageScope,
		policy.ExecutionMode,
		policy.CadenceKind,
		policy.TimeLocal,
		r.json(policy.Weekdays),
		policy.ApprovalTimeoutMinutes,
		r.json(policy.PolicyBlackouts),
		now,
		now,
	)
	if err != nil {
		return Policy{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Policy{}, err
	}
	return r.GetPolicy(id)
}

func (r *SQLiteRepository) UpdatePolicy(id int64, policy Policy) (Policy, error) {
	if id <= 0 {
		return Policy{}, sql.ErrNoRows
	}
	now := r.now()
	result, err := r.database().Exec(`
		UPDATE update_policies
		   SET name = ?, enabled = ?, target_tag = ?, include_tags_json = ?, exclude_tags_json = ?,
		       target_servers_json = ?, package_scope = ?, execution_mode = ?,
		       cadence_kind = ?, time_local = ?, weekdays_json = ?, approval_timeout_minutes = ?,
		       policy_blackouts_json = ?, updated_at = ?
		 WHERE id = ?
	`,
		policy.Name,
		BoolToInt(policy.Enabled),
		policy.TargetTag,
		r.json(policy.IncludeTags),
		r.json(policy.ExcludeTags),
		r.json(policy.TargetServers),
		policy.PackageScope,
		policy.ExecutionMode,
		policy.CadenceKind,
		policy.TimeLocal,
		r.json(policy.Weekdays),
		policy.ApprovalTimeoutMinutes,
		r.json(policy.PolicyBlackouts),
		now,
		id,
	)
	if err != nil {
		return Policy{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Policy{}, err
	}
	if rows == 0 {
		return Policy{}, sql.ErrNoRows
	}
	return r.GetPolicy(id)
}

func (r *SQLiteRepository) DeletePolicy(id int64) error {
	tx, err := r.database().Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM update_policy_overrides WHERE policy_id = ?", id); err != nil {
		_ = tx.Rollback()
		return err
	}
	result, err := tx.Exec("DELETE FROM update_policies WHERE id = ?", id)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if rows == 0 {
		_ = tx.Rollback()
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func scanPolicyRow(scanner interface{ Scan(dest ...any) error }) (Policy, error) {
	var policy Policy
	var enabledInt int
	var weekdaysJSON string
	var policyBlackoutsJSON string
	var includeTagsJSON string
	var excludeTagsJSON string
	var targetServersJSON string
	err := scanner.Scan(
		&policy.ID,
		&policy.Name,
		&enabledInt,
		&policy.TargetTag,
		&includeTagsJSON,
		&excludeTagsJSON,
		&targetServersJSON,
		&policy.PackageScope,
		&policy.ExecutionMode,
		&policy.CadenceKind,
		&policy.TimeLocal,
		&weekdaysJSON,
		&policy.ApprovalTimeoutMinutes,
		&policyBlackoutsJSON,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		return Policy{}, err
	}
	policy.Enabled = enabledInt != 0
	policy.IncludeTags = ParseStringListJSON(includeTagsJSON)
	policy.ExcludeTags = ParseStringListJSON(excludeTagsJSON)
	policy.TargetServers = ParseStringListJSON(targetServersJSON)
	policy.Weekdays = ParseWeekdaysJSON(weekdaysJSON)
	blackouts, err := ParseBlackouts(policyBlackoutsJSON)
	if err != nil {
		return Policy{}, err
	}
	policy.PolicyBlackouts = blackouts
	return policy, nil
}

func (r *SQLiteRepository) ListOverrides(policyID int64) ([]Override, error) {
	rows, err := r.database().Query(`
		SELECT policy_id, server_name, disabled, created_at, updated_at
		  FROM update_policy_overrides
		 WHERE policy_id = ?
		 ORDER BY server_name ASC
	`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Override, 0)
	for rows.Next() {
		var item Override
		var disabledInt int
		if err := rows.Scan(&item.PolicyID, &item.ServerName, &disabledInt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Disabled = disabledInt != 0
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (r *SQLiteRepository) LoadAllOverrides() (map[int64]map[string]bool, error) {
	rows, err := r.database().Query(`SELECT policy_id, server_name, disabled FROM update_policy_overrides`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	overrides := make(map[int64]map[string]bool)
	for rows.Next() {
		var policyID int64
		var serverName string
		var disabledInt int
		if err := rows.Scan(&policyID, &serverName, &disabledInt); err != nil {
			return nil, err
		}
		if _, exists := overrides[policyID]; !exists {
			overrides[policyID] = make(map[string]bool)
		}
		overrides[policyID][serverName] = disabledInt != 0
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return overrides, nil
}

func (r *SQLiteRepository) SetOverride(policyID int64, serverName string, disabled bool) (Override, error) {
	serverName = strings.TrimSpace(serverName)
	if policyID <= 0 || serverName == "" {
		return Override{}, errors.New("policy_id and server_name are required")
	}
	now := r.now()
	if !disabled {
		if _, err := r.database().Exec(`
			DELETE FROM update_policy_overrides
			 WHERE policy_id = ? AND server_name = ?
		`, policyID, serverName); err != nil {
			return Override{}, err
		}
		return Override{
			PolicyID:   policyID,
			ServerName: serverName,
			Disabled:   false,
			UpdatedAt:  now,
		}, nil
	}
	if _, err := r.database().Exec(`
		INSERT INTO update_policy_overrides (policy_id, server_name, disabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(policy_id, server_name) DO UPDATE SET
			disabled = excluded.disabled,
			updated_at = excluded.updated_at
	`, policyID, serverName, BoolToInt(disabled), now, now); err != nil {
		return Override{}, err
	}
	var item Override
	var disabledInt int
	if err := r.database().QueryRow(`
		SELECT policy_id, server_name, disabled, created_at, updated_at
		  FROM update_policy_overrides
		 WHERE policy_id = ? AND server_name = ?
	`, policyID, serverName).Scan(&item.PolicyID, &item.ServerName, &disabledInt, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return Override{}, err
	}
	item.Disabled = disabledInt != 0
	return item, nil
}

func (r *SQLiteRepository) RenameOverridesServerTx(tx *sql.Tx, oldServerName, newServerName string) error {
	if tx == nil {
		return errors.New("tx is required")
	}
	oldServerName = strings.TrimSpace(oldServerName)
	newServerName = strings.TrimSpace(newServerName)
	if oldServerName == "" || newServerName == "" || oldServerName == newServerName {
		return nil
	}
	now := r.now()
	if _, err := tx.Exec(`
		INSERT INTO update_policy_overrides (policy_id, server_name, disabled, created_at, updated_at)
		SELECT policy_id, ?, disabled, created_at, ?
		  FROM update_policy_overrides
		 WHERE server_name = ?
		ON CONFLICT(policy_id, server_name) DO UPDATE SET
			disabled = excluded.disabled,
			updated_at = excluded.updated_at
	`, newServerName, now, oldServerName); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM update_policy_overrides WHERE server_name = ?`, oldServerName); err != nil {
		return err
	}
	return nil
}

func (r *SQLiteRepository) RenameTargetServersTx(tx *sql.Tx, oldServerName, newServerName string) error {
	if tx == nil {
		return errors.New("tx is required")
	}
	oldServerName = strings.TrimSpace(oldServerName)
	newServerName = strings.TrimSpace(newServerName)
	if oldServerName == "" || newServerName == "" {
		return nil
	}
	rows, err := tx.Query(`SELECT id, target_servers_json FROM update_policies`)
	if err != nil {
		return err
	}
	type policyTargetUpdate struct {
		id      int64
		targets []string
	}
	updates := make([]policyTargetUpdate, 0)
	for rows.Next() {
		var id int64
		var rawTargets string
		if err := rows.Scan(&id, &rawTargets); err != nil {
			_ = rows.Close()
			return err
		}
		targets := ParseStringListJSON(rawTargets)
		changed := false
		for i, target := range targets {
			if strings.EqualFold(strings.TrimSpace(target), oldServerName) {
				targets[i] = newServerName
				changed = true
			}
		}
		if changed {
			updates = append(updates, policyTargetUpdate{
				id:      id,
				targets: NormalizeStringList(targets),
			})
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	now := r.now()
	for _, update := range updates {
		if _, err := tx.Exec(`
			UPDATE update_policies
			   SET target_servers_json = ?, updated_at = ?
			 WHERE id = ?
		`, r.json(update.targets), now, update.id); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) PruneOverridesForServersTx(tx *sql.Tx, activeServers []servers.Server) error {
	if tx == nil {
		return errors.New("tx is required")
	}
	if len(activeServers) == 0 {
		_, err := tx.Exec("DELETE FROM update_policy_overrides")
		return err
	}
	seen := make(map[string]struct{}, len(activeServers))
	names := make([]string, 0, len(activeServers))
	for _, server := range activeServers {
		name := strings.TrimSpace(server.Name)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if len(names) == 0 {
		_, err := tx.Exec("DELETE FROM update_policy_overrides")
		return err
	}
	sortStrings(names)
	placeholders := strings.TrimRight(strings.Repeat("?,", len(names)), ",")
	args := make([]any, 0, len(names))
	for _, name := range names {
		args = append(args, name)
	}
	query := "DELETE FROM update_policy_overrides WHERE server_name NOT IN (" + placeholders + ")"
	_, err := tx.Exec(query, args...)
	return err
}

func (r *SQLiteRepository) CreateRun(run Run) (Run, bool, error) {
	now := r.now()
	if strings.TrimSpace(run.Status) == "" {
		run.Status = RunQueued
	}
	if strings.TrimSpace(run.ResultJSON) == "" {
		run.ResultJSON = "{}"
	}
	result, err := r.database().Exec(`
		INSERT INTO update_policy_runs (
			policy_id, policy_name, server_name, scheduled_for_utc, execution_mode, package_scope,
			status, reason, summary, job_id, result_json, created_at, updated_at, started_at, finished_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		run.PolicyID,
		run.PolicyName,
		run.ServerName,
		run.ScheduledForUTC,
		run.ExecutionMode,
		run.PackageScope,
		run.Status,
		run.Reason,
		run.Summary,
		run.JobID,
		run.ResultJSON,
		now,
		now,
		run.StartedAt,
		run.FinishedAt,
	)
	if err != nil {
		if IsSQLiteUniqueConstraint(err) {
			existing, getErr := r.FindRun(run.PolicyID, run.ServerName, run.ScheduledForUTC)
			if getErr != nil {
				return Run{}, false, getErr
			}
			return existing, false, nil
		}
		return Run{}, false, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Run{}, false, err
	}
	created, err := r.GetRun(id)
	if err != nil {
		return Run{}, false, err
	}
	return created, true, nil
}

func (r *SQLiteRepository) FindRun(policyID int64, serverName, scheduledForUTC string) (Run, error) {
	row := r.database().QueryRow(`
		SELECT id, policy_id, policy_name, server_name, scheduled_for_utc, execution_mode, package_scope,
		       status, reason, summary, job_id, result_json, created_at, updated_at, started_at, finished_at
		  FROM update_policy_runs
		 WHERE policy_id = ? AND server_name = ? AND scheduled_for_utc = ?
	`, policyID, serverName, scheduledForUTC)
	return scanRunRow(row)
}

func (r *SQLiteRepository) GetRun(id int64) (Run, error) {
	row := r.database().QueryRow(`
		SELECT id, policy_id, policy_name, server_name, scheduled_for_utc, execution_mode, package_scope,
		       status, reason, summary, job_id, result_json, created_at, updated_at, started_at, finished_at
		  FROM update_policy_runs
		 WHERE id = ?
	`, id)
	return scanRunRow(row)
}

func scanRunRow(scanner interface{ Scan(dest ...any) error }) (Run, error) {
	var run Run
	err := scanner.Scan(
		&run.ID,
		&run.PolicyID,
		&run.PolicyName,
		&run.ServerName,
		&run.ScheduledForUTC,
		&run.ExecutionMode,
		&run.PackageScope,
		&run.Status,
		&run.Reason,
		&run.Summary,
		&run.JobID,
		&run.ResultJSON,
		&run.CreatedAt,
		&run.UpdatedAt,
		&run.StartedAt,
		&run.FinishedAt,
	)
	return run, err
}

func (r *SQLiteRepository) UpdateRun(id int64, update RunUpdate) error {
	if id <= 0 {
		return nil
	}
	now := r.now()
	setClauses := []string{"updated_at = ?"}
	args := []any{now}
	if update.Status != nil {
		setClauses = append(setClauses, "status = ?")
		args = append(args, strings.TrimSpace(*update.Status))
	}
	if update.Reason != nil {
		setClauses = append(setClauses, "reason = ?")
		args = append(args, strings.TrimSpace(*update.Reason))
	}
	if update.Summary != nil {
		setClauses = append(setClauses, "summary = ?")
		args = append(args, strings.TrimSpace(*update.Summary))
	}
	if update.JobID != nil {
		setClauses = append(setClauses, "job_id = ?")
		args = append(args, strings.TrimSpace(*update.JobID))
	}
	if update.ResultJSON != nil {
		setClauses = append(setClauses, "result_json = ?")
		args = append(args, strings.TrimSpace(*update.ResultJSON))
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
	_, err := r.database().Exec("UPDATE update_policy_runs SET "+strings.Join(setClauses, ", ")+" WHERE id = ?", args...)
	return err
}

func (r *SQLiteRepository) ListRuns(limit int) ([]Run, error) {
	if limit <= 0 {
		limit = DefaultRunsLimit
	}
	rows, err := r.database().Query(`
		SELECT id, policy_id, policy_name, server_name, scheduled_for_utc, execution_mode, package_scope,
		       status, reason, summary, job_id, result_json, created_at, updated_at, started_at, finished_at
		  FROM update_policy_runs
		 ORDER BY scheduled_for_utc DESC, id DESC
		 LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Run, 0, limit)
	for rows.Next() {
		run, err := scanRunRow(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (r *SQLiteRepository) MarkInterruptedRuns() error {
	now := r.now()
	_, err := r.database().Exec(`
		UPDATE update_policy_runs
		   SET status = ?, reason = ?, summary = CASE
				WHEN TRIM(summary) = '' THEN 'Interrupted during restart recovery'
				ELSE summary
			   END,
		       finished_at = CASE WHEN TRIM(finished_at) = '' THEN ? ELSE finished_at END,
		       updated_at = ?
		 WHERE status IN (?, ?, ?)
	`, RunInterrupted, RunReasonRestart, now, now, RunQueued, RunRunning, RunWaitingApproval)
	return err
}

func IsSQLiteUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") || strings.Contains(msg, "constraint failed")
}
