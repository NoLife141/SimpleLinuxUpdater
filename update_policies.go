package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

const (
	updatePolicyExecutionScanOnly         = "scan_only"
	updatePolicyExecutionApprovalRequired = "approval_required"
	updatePolicyExecutionAutoApply        = "auto_apply"

	updatePolicyPackageScopeSecurity = "security"
	updatePolicyPackageScopeFull     = "full"

	updatePolicyCadenceDaily  = "daily"
	updatePolicyCadenceWeekly = "weekly"

	updatePolicyRunQueued          = "queued"
	updatePolicyRunRunning         = "running"
	updatePolicyRunWaitingApproval = "waiting_approval"
	updatePolicyRunSucceeded       = "succeeded"
	updatePolicyRunFailed          = "failed"
	updatePolicyRunSkipped         = "skipped"
	updatePolicyRunCancelled       = "cancelled"
	updatePolicyRunInterrupted     = "interrupted"

	updatePolicyRunReasonBlackout    = "blackout"
	updatePolicyRunReasonBusy        = "busy"
	updatePolicyRunReasonSuperseded  = "superseded"
	updatePolicyRunReasonRestart     = "restart"
	updatePolicyRunReasonNoMatch     = "no_match"
	updatePolicyRunReasonMissing     = "missing"
	updatePolicyRunReasonMaintenance = "maintenance"
	updatePolicyRunReasonPersistence = "persistence"

	updatePolicyGlobalBlackoutsSetting     = "update_policy_global_blackouts"
	defaultScheduledApprovalTimeoutMinutes = 720
	updatePolicyTickInterval               = time.Minute
)

var (
	updatePolicySchedulerOnce sync.Once
	updatePolicyTickMu        sync.Mutex
	errUpdatePolicyValidation = errors.New("update policy validation")
)

func wrapUpdatePolicyValidationError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", errUpdatePolicyValidation, err)
}

func isUpdatePolicyValidationError(err error) bool {
	return errors.Is(err, errUpdatePolicyValidation)
}

type UpdatePolicyBlackoutWindow struct {
	Weekdays  []string `json:"weekdays"`
	StartTime string   `json:"start_time"`
	EndTime   string   `json:"end_time"`
}

type UpdatePolicy struct {
	ID                     int64                        `json:"id"`
	Name                   string                       `json:"name"`
	Enabled                bool                         `json:"enabled"`
	TargetTag              string                       `json:"target_tag"`
	PackageScope           string                       `json:"package_scope"`
	ExecutionMode          string                       `json:"execution_mode"`
	CadenceKind            string                       `json:"cadence_kind"`
	TimeLocal              string                       `json:"time_local"`
	Weekdays               []string                     `json:"weekdays"`
	ApprovalTimeoutMinutes int                          `json:"approval_timeout_minutes"`
	PolicyBlackouts        []UpdatePolicyBlackoutWindow `json:"policy_blackouts"`
	CreatedAt              string                       `json:"created_at"`
	UpdatedAt              string                       `json:"updated_at"`
	MatchedServers         []string                     `json:"matched_servers,omitempty"`
}

type UpdatePolicyOverride struct {
	PolicyID    int64  `json:"policy_id"`
	ServerName  string `json:"server_name"`
	Disabled    bool   `json:"disabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	PolicyName  string `json:"policy_name,omitempty"`
	TargetTag   string `json:"target_tag,omitempty"`
	ServerMatch bool   `json:"server_match,omitempty"`
}

type UpdatePolicyRun struct {
	ID              int64  `json:"id"`
	PolicyID        int64  `json:"policy_id"`
	PolicyName      string `json:"policy_name"`
	ServerName      string `json:"server_name"`
	ScheduledForUTC string `json:"scheduled_for_utc"`
	ExecutionMode   string `json:"execution_mode"`
	PackageScope    string `json:"package_scope"`
	Status          string `json:"status"`
	Reason          string `json:"reason"`
	Summary         string `json:"summary"`
	JobID           string `json:"job_id"`
	ResultJSON      string `json:"result_json"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
}

type UpdatePolicySettingsResponse struct {
	Timezone        string                       `json:"timezone"`
	GlobalBlackouts []UpdatePolicyBlackoutWindow `json:"global_blackouts"`
}

type updatePolicyRunUpdate struct {
	Status     *string
	Reason     *string
	Summary    *string
	JobID      *string
	ResultJSON *string
	StartedAt  *string
	FinishedAt *string
}

type scheduledJobBehavior struct {
	ApprovalTimeout  time.Duration
	AutoApproveScope string
}

type scheduledJobDiscovery struct {
	PendingPackageCount  int             `json:"pending_package_count"`
	SecurityPackageCount int             `json:"security_package_count"`
	Upgradable           []string        `json:"upgradable"`
	PendingUpdates       []PendingUpdate `json:"pending_updates"`
}

type scheduledJobMeta struct {
	Trigger                string                 `json:"trigger,omitempty"`
	PolicyID               int64                  `json:"policy_id,omitempty"`
	PolicyName             string                 `json:"policy_name,omitempty"`
	ScheduledFor           string                 `json:"scheduled_for,omitempty"`
	ExecutionMode          string                 `json:"execution_mode,omitempty"`
	PackageScope           string                 `json:"package_scope,omitempty"`
	ApprovalTimeoutMinutes int                    `json:"approval_timeout_minutes,omitempty"`
	AutoApproveScope       string                 `json:"auto_approve_scope,omitempty"`
	Discovery              *scheduledJobDiscovery `json:"discovery,omitempty"`
}

type scheduledPolicyCandidate struct {
	policy          UpdatePolicy
	server          Server
	scheduledForUTC string
}

func ensureUpdatePolicySchema(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS update_policies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			target_tag TEXT NOT NULL,
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
	return nil
}

func currentAppTimezoneName() string {
	if time.Local == nil {
		return "Local"
	}
	return time.Local.String()
}

func getSettingValue(key string) (string, error) {
	var value string
	err := getDB().QueryRow("SELECT value FROM settings WHERE key = ?", strings.TrimSpace(key)).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func upsertSettingValue(key, value string) error {
	_, err := getDB().Exec(
		"INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		strings.TrimSpace(key),
		value,
	)
	return err
}

func parseUpdatePolicyBlackouts(raw string) ([]UpdatePolicyBlackoutWindow, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []UpdatePolicyBlackoutWindow{}, nil
	}
	var windows []UpdatePolicyBlackoutWindow
	if err := json.Unmarshal([]byte(raw), &windows); err != nil {
		return nil, err
	}
	return normalizeBlackoutWindows(windows)
}

func loadGlobalUpdatePolicyBlackouts() ([]UpdatePolicyBlackoutWindow, error) {
	raw, err := getSettingValue(updatePolicyGlobalBlackoutsSetting)
	if err != nil {
		return nil, err
	}
	return parseUpdatePolicyBlackouts(raw)
}

func saveGlobalUpdatePolicyBlackouts(windows []UpdatePolicyBlackoutWindow) ([]UpdatePolicyBlackoutWindow, error) {
	normalized, err := normalizeBlackoutWindows(windows)
	if err != nil {
		return nil, wrapUpdatePolicyValidationError(err)
	}
	if err := upsertSettingValue(updatePolicyGlobalBlackoutsSetting, marshalJobJSON(normalized)); err != nil {
		return nil, err
	}
	return normalized, nil
}

func parseWeekdaysJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	var weekdays []string
	if err := json.Unmarshal([]byte(raw), &weekdays); err != nil {
		return []string{}
	}
	normalized, err := normalizeWeekdays(weekdays)
	if err != nil {
		return []string{}
	}
	return normalized
}

func normalizeWeekdayToken(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "mon", "monday":
		return "mon", nil
	case "tue", "tues", "tuesday":
		return "tue", nil
	case "wed", "wednesday":
		return "wed", nil
	case "thu", "thur", "thurs", "thursday":
		return "thu", nil
	case "fri", "friday":
		return "fri", nil
	case "sat", "saturday":
		return "sat", nil
	case "sun", "sunday":
		return "sun", nil
	default:
		return "", fmt.Errorf("invalid weekday %q", raw)
	}
}

func normalizeWeekdays(weekdays []string) ([]string, error) {
	if len(weekdays) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(weekdays))
	out := make([]string, 0, len(weekdays))
	for _, weekday := range weekdays {
		normalized, err := normalizeWeekdayToken(weekday)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		return weekdayOrder(out[i]) < weekdayOrder(out[j])
	})
	return out, nil
}

func weekdayOrder(day string) int {
	switch day {
	case "mon":
		return 1
	case "tue":
		return 2
	case "wed":
		return 3
	case "thu":
		return 4
	case "fri":
		return 5
	case "sat":
		return 6
	case "sun":
		return 7
	default:
		return 99
	}
}

func normalizeTimeLocal(raw string) (string, error) {
	parsed, err := time.Parse("15:04", strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("time_local must be HH:MM")
	}
	return parsed.Format("15:04"), nil
}

func parseTimeLocalMinutes(raw string) (int, error) {
	normalized, err := normalizeTimeLocal(raw)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(normalized, ":")
	hour, _ := strconv.Atoi(parts[0])
	minute, _ := strconv.Atoi(parts[1])
	return hour*60 + minute, nil
}

func normalizeBlackoutWindows(windows []UpdatePolicyBlackoutWindow) ([]UpdatePolicyBlackoutWindow, error) {
	if len(windows) == 0 {
		return []UpdatePolicyBlackoutWindow{}, nil
	}
	normalized := make([]UpdatePolicyBlackoutWindow, 0, len(windows))
	for _, window := range windows {
		weekdays, err := normalizeWeekdays(window.Weekdays)
		if err != nil {
			return nil, err
		}
		if len(weekdays) == 0 {
			return nil, errors.New("blackout weekdays are required")
		}
		startTime, err := normalizeTimeLocal(window.StartTime)
		if err != nil {
			return nil, fmt.Errorf("invalid blackout start_time: %w", err)
		}
		endTime, err := normalizeTimeLocal(window.EndTime)
		if err != nil {
			return nil, fmt.Errorf("invalid blackout end_time: %w", err)
		}
		startMinutes, _ := parseTimeLocalMinutes(startTime)
		endMinutes, _ := parseTimeLocalMinutes(endTime)
		if startMinutes == endMinutes {
			return nil, errors.New("blackout start_time and end_time cannot be identical")
		}
		normalized = append(normalized, UpdatePolicyBlackoutWindow{
			Weekdays:  weekdays,
			StartTime: startTime,
			EndTime:   endTime,
		})
	}
	return normalized, nil
}

func normalizeUpdatePolicy(policy *UpdatePolicy) error {
	if policy == nil {
		return errors.New("policy is required")
	}
	policy.Name = truncateString(policy.Name, 255)
	policy.Name = strings.TrimSpace(policy.Name)
	if policy.Name == "" {
		return errors.New("name is required")
	}
	policy.TargetTag = strings.TrimSpace(policy.TargetTag)
	if policy.TargetTag == "" {
		return errors.New("target_tag is required")
	}
	switch strings.ToLower(strings.TrimSpace(policy.PackageScope)) {
	case updatePolicyPackageScopeSecurity:
		policy.PackageScope = updatePolicyPackageScopeSecurity
	case updatePolicyPackageScopeFull:
		policy.PackageScope = updatePolicyPackageScopeFull
	default:
		return errors.New("package_scope must be 'security' or 'full'")
	}
	switch strings.ToLower(strings.TrimSpace(policy.ExecutionMode)) {
	case updatePolicyExecutionScanOnly:
		policy.ExecutionMode = updatePolicyExecutionScanOnly
	case updatePolicyExecutionApprovalRequired:
		policy.ExecutionMode = updatePolicyExecutionApprovalRequired
	case updatePolicyExecutionAutoApply:
		policy.ExecutionMode = updatePolicyExecutionAutoApply
	default:
		return errors.New("execution_mode must be 'scan_only', 'approval_required', or 'auto_apply'")
	}
	switch strings.ToLower(strings.TrimSpace(policy.CadenceKind)) {
	case updatePolicyCadenceDaily:
		policy.CadenceKind = updatePolicyCadenceDaily
	case updatePolicyCadenceWeekly:
		policy.CadenceKind = updatePolicyCadenceWeekly
	default:
		return errors.New("cadence_kind must be 'daily' or 'weekly'")
	}
	timeLocal, err := normalizeTimeLocal(policy.TimeLocal)
	if err != nil {
		return err
	}
	policy.TimeLocal = timeLocal
	weekdays, err := normalizeWeekdays(policy.Weekdays)
	if err != nil {
		return err
	}
	if policy.CadenceKind == updatePolicyCadenceWeekly && len(weekdays) == 0 {
		return errors.New("weekly policies require at least one weekday")
	}
	if policy.CadenceKind == updatePolicyCadenceDaily {
		weekdays = []string{}
	}
	policy.Weekdays = weekdays
	policyBlackouts, err := normalizeBlackoutWindows(policy.PolicyBlackouts)
	if err != nil {
		return err
	}
	policy.PolicyBlackouts = policyBlackouts
	if policy.ExecutionMode == updatePolicyExecutionApprovalRequired {
		if policy.ApprovalTimeoutMinutes <= 0 {
			policy.ApprovalTimeoutMinutes = defaultScheduledApprovalTimeoutMinutes
		}
	} else {
		policy.ApprovalTimeoutMinutes = 0
	}
	return nil
}

func scanUpdatePolicyRow(scanner interface {
	Scan(dest ...any) error
}) (UpdatePolicy, error) {
	var policy UpdatePolicy
	var enabledInt int
	var weekdaysJSON string
	var policyBlackoutsJSON string
	err := scanner.Scan(
		&policy.ID,
		&policy.Name,
		&enabledInt,
		&policy.TargetTag,
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
		return UpdatePolicy{}, err
	}
	policy.Enabled = enabledInt != 0
	policy.Weekdays = parseWeekdaysJSON(weekdaysJSON)
	blackouts, err := parseUpdatePolicyBlackouts(policyBlackoutsJSON)
	if err != nil {
		return UpdatePolicy{}, err
	}
	policy.PolicyBlackouts = blackouts
	return policy, nil
}

func listUpdatePolicies() ([]UpdatePolicy, error) {
	rows, err := getDB().Query(`
		SELECT id, name, enabled, target_tag, package_scope, execution_mode, cadence_kind, time_local,
		       weekdays_json, approval_timeout_minutes, policy_blackouts_json, created_at, updated_at
		  FROM update_policies
		 ORDER BY created_at ASC, id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	policies := make([]UpdatePolicy, 0)
	for rows.Next() {
		policy, scanErr := scanUpdatePolicyRow(rows)
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

func getUpdatePolicy(id int64) (UpdatePolicy, error) {
	row := getDB().QueryRow(`
		SELECT id, name, enabled, target_tag, package_scope, execution_mode, cadence_kind, time_local,
		       weekdays_json, approval_timeout_minutes, policy_blackouts_json, created_at, updated_at
		  FROM update_policies
		 WHERE id = ?
	`, id)
	return scanUpdatePolicyRow(row)
}

func createUpdatePolicy(policy UpdatePolicy) (UpdatePolicy, error) {
	if err := normalizeUpdatePolicy(&policy); err != nil {
		return UpdatePolicy{}, wrapUpdatePolicyValidationError(err)
	}
	now := jobTimestampNow()
	result, err := getDB().Exec(`
		INSERT INTO update_policies (
			name, enabled, target_tag, package_scope, execution_mode, cadence_kind, time_local,
			weekdays_json, approval_timeout_minutes, policy_blackouts_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		policy.Name,
		boolToInt(policy.Enabled),
		policy.TargetTag,
		policy.PackageScope,
		policy.ExecutionMode,
		policy.CadenceKind,
		policy.TimeLocal,
		marshalJobJSON(policy.Weekdays),
		policy.ApprovalTimeoutMinutes,
		marshalJobJSON(policy.PolicyBlackouts),
		now,
		now,
	)
	if err != nil {
		return UpdatePolicy{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return UpdatePolicy{}, err
	}
	return getUpdatePolicy(id)
}

func updateUpdatePolicy(id int64, policy UpdatePolicy) (UpdatePolicy, error) {
	if id <= 0 {
		return UpdatePolicy{}, sql.ErrNoRows
	}
	policy.ID = id
	if err := normalizeUpdatePolicy(&policy); err != nil {
		return UpdatePolicy{}, wrapUpdatePolicyValidationError(err)
	}
	now := jobTimestampNow()
	result, err := getDB().Exec(`
		UPDATE update_policies
		   SET name = ?, enabled = ?, target_tag = ?, package_scope = ?, execution_mode = ?,
		       cadence_kind = ?, time_local = ?, weekdays_json = ?, approval_timeout_minutes = ?,
		       policy_blackouts_json = ?, updated_at = ?
		 WHERE id = ?
	`,
		policy.Name,
		boolToInt(policy.Enabled),
		policy.TargetTag,
		policy.PackageScope,
		policy.ExecutionMode,
		policy.CadenceKind,
		policy.TimeLocal,
		marshalJobJSON(policy.Weekdays),
		policy.ApprovalTimeoutMinutes,
		marshalJobJSON(policy.PolicyBlackouts),
		now,
		id,
	)
	if err != nil {
		return UpdatePolicy{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return UpdatePolicy{}, err
	}
	if rows == 0 {
		return UpdatePolicy{}, sql.ErrNoRows
	}
	return getUpdatePolicy(id)
}

func deleteUpdatePolicy(id int64) error {
	tx, err := getDB().Begin()
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

func listUpdatePolicyOverrides(policyID int64) ([]UpdatePolicyOverride, error) {
	rows, err := getDB().Query(`
		SELECT policy_id, server_name, disabled, created_at, updated_at
		  FROM update_policy_overrides
		 WHERE policy_id = ?
		 ORDER BY server_name ASC
	`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]UpdatePolicyOverride, 0)
	for rows.Next() {
		var item UpdatePolicyOverride
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

func loadAllUpdatePolicyOverrides() (map[int64]map[string]bool, error) {
	rows, err := getDB().Query(`SELECT policy_id, server_name, disabled FROM update_policy_overrides`)
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

func setUpdatePolicyOverride(policyID int64, serverName string, disabled bool) (UpdatePolicyOverride, error) {
	serverName = strings.TrimSpace(serverName)
	if policyID <= 0 || serverName == "" {
		return UpdatePolicyOverride{}, errors.New("policy_id and server_name are required")
	}
	now := jobTimestampNow()
	if !disabled {
		if _, err := getDB().Exec(`
			DELETE FROM update_policy_overrides
			 WHERE policy_id = ? AND server_name = ?
		`, policyID, serverName); err != nil {
			return UpdatePolicyOverride{}, err
		}
		return UpdatePolicyOverride{
			PolicyID:   policyID,
			ServerName: serverName,
			Disabled:   false,
			UpdatedAt:  now,
		}, nil
	}
	if _, err := getDB().Exec(`
		INSERT INTO update_policy_overrides (policy_id, server_name, disabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(policy_id, server_name) DO UPDATE SET
			disabled = excluded.disabled,
			updated_at = excluded.updated_at
	`, policyID, serverName, boolToInt(disabled), now, now); err != nil {
		return UpdatePolicyOverride{}, err
	}
	var item UpdatePolicyOverride
	var disabledInt int
	if err := getDB().QueryRow(`
		SELECT policy_id, server_name, disabled, created_at, updated_at
		  FROM update_policy_overrides
		 WHERE policy_id = ? AND server_name = ?
	`, policyID, serverName).Scan(&item.PolicyID, &item.ServerName, &disabledInt, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return UpdatePolicyOverride{}, err
	}
	item.Disabled = disabledInt != 0
	return item, nil
}

func renameUpdatePolicyOverridesServerTx(tx *sql.Tx, oldServerName, newServerName string) error {
	if tx == nil {
		return errors.New("tx is required")
	}
	oldServerName = strings.TrimSpace(oldServerName)
	newServerName = strings.TrimSpace(newServerName)
	if oldServerName == "" || newServerName == "" || oldServerName == newServerName {
		return nil
	}

	now := jobTimestampNow()
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

func renameUpdatePolicyOverridesServer(oldServerName, newServerName string) error {
	tx, err := getDB().Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := renameUpdatePolicyOverridesServerTx(tx, oldServerName, newServerName); err != nil {
		return err
	}

	return tx.Commit()
}

func pruneUpdatePolicyOverridesForServersTx(tx *sql.Tx, activeServers []Server) error {
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
	sort.Strings(names)
	placeholders := strings.TrimRight(strings.Repeat("?,", len(names)), ",")
	args := make([]any, 0, len(names))
	for _, name := range names {
		args = append(args, name)
	}
	query := "DELETE FROM update_policy_overrides WHERE server_name NOT IN (" + placeholders + ")"
	_, err := tx.Exec(query, args...)
	return err
}

func createUpdatePolicyRun(run UpdatePolicyRun) (UpdatePolicyRun, bool, error) {
	now := jobTimestampNow()
	if strings.TrimSpace(run.Status) == "" {
		run.Status = updatePolicyRunQueued
	}
	if strings.TrimSpace(run.ResultJSON) == "" {
		run.ResultJSON = "{}"
	}
	result, err := getDB().Exec(`
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
		if isSQLiteUniqueConstraint(err) {
			existing, getErr := findUpdatePolicyRun(run.PolicyID, run.ServerName, run.ScheduledForUTC)
			if getErr != nil {
				return UpdatePolicyRun{}, false, getErr
			}
			return existing, false, nil
		}
		return UpdatePolicyRun{}, false, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return UpdatePolicyRun{}, false, err
	}
	created, err := getUpdatePolicyRun(id)
	if err != nil {
		return UpdatePolicyRun{}, false, err
	}
	return created, true, nil
}

func findUpdatePolicyRun(policyID int64, serverName, scheduledForUTC string) (UpdatePolicyRun, error) {
	row := getDB().QueryRow(`
		SELECT id, policy_id, policy_name, server_name, scheduled_for_utc, execution_mode, package_scope,
		       status, reason, summary, job_id, result_json, created_at, updated_at, started_at, finished_at
		  FROM update_policy_runs
		 WHERE policy_id = ? AND server_name = ? AND scheduled_for_utc = ?
	`, policyID, serverName, scheduledForUTC)
	return scanUpdatePolicyRunRow(row)
}

func getUpdatePolicyRun(id int64) (UpdatePolicyRun, error) {
	row := getDB().QueryRow(`
		SELECT id, policy_id, policy_name, server_name, scheduled_for_utc, execution_mode, package_scope,
		       status, reason, summary, job_id, result_json, created_at, updated_at, started_at, finished_at
		  FROM update_policy_runs
		 WHERE id = ?
	`, id)
	return scanUpdatePolicyRunRow(row)
}

func scanUpdatePolicyRunRow(scanner interface {
	Scan(dest ...any) error
}) (UpdatePolicyRun, error) {
	var run UpdatePolicyRun
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

func updateUpdatePolicyRun(id int64, update updatePolicyRunUpdate) error {
	if id <= 0 {
		return nil
	}
	now := jobTimestampNow()
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
	_, err := getDB().Exec("UPDATE update_policy_runs SET "+strings.Join(setClauses, ", ")+" WHERE id = ?", args...)
	return err
}

func listUpdatePolicyRuns(limit int) ([]UpdatePolicyRun, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := getDB().Query(`
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

	items := make([]UpdatePolicyRun, 0, limit)
	for rows.Next() {
		run, err := scanUpdatePolicyRunRow(rows)
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

func markInterruptedUpdatePolicyRuns() error {
	now := jobTimestampNow()
	_, err := getDB().Exec(`
		UPDATE update_policy_runs
		   SET status = ?, reason = ?, summary = CASE
				WHEN TRIM(summary) = '' THEN 'Interrupted during restart recovery'
				ELSE summary
			   END,
		       finished_at = CASE WHEN TRIM(finished_at) = '' THEN ? ELSE finished_at END,
		       updated_at = ?
		 WHERE status IN (?, ?, ?)
	`, updatePolicyRunInterrupted, updatePolicyRunReasonRestart, now, now, updatePolicyRunQueued, updatePolicyRunRunning, updatePolicyRunWaitingApproval)
	return err
}

func isSQLiteUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") || strings.Contains(msg, "constraint failed")
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func serverHasTag(server Server, tag string) bool {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return false
	}
	for _, candidate := range server.Tags {
		if strings.EqualFold(strings.TrimSpace(candidate), tag) {
			return true
		}
	}
	return false
}

func snapshotServers() []Server {
	mu.Lock()
	defer mu.Unlock()
	return cloneServers(servers)
}

func serverExistsByName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, server := range snapshotServers() {
		if server.Name == name {
			return true
		}
	}
	return false
}

func policyMatchesServer(policy UpdatePolicy, server Server, overrides map[int64]map[string]bool) bool {
	if !policy.Enabled {
		return false
	}
	if !serverHasTag(server, policy.TargetTag) {
		return false
	}
	if perPolicy := overrides[policy.ID]; perPolicy != nil && perPolicy[server.Name] {
		return false
	}
	return true
}

func enrichPoliciesWithMatches(policies []UpdatePolicy) []UpdatePolicy {
	serversSnapshot := snapshotServers()
	overrides, err := loadAllUpdatePolicyOverrides()
	if err != nil {
		return policies
	}
	for i := range policies {
		matched := make([]string, 0)
		for _, server := range serversSnapshot {
			if policyMatchesServer(policies[i], server, overrides) {
				matched = append(matched, server.Name)
			}
		}
		sort.Strings(matched)
		policies[i].MatchedServers = matched
	}
	return policies
}

func weekdayMatchesLocal(weekdays []string, t time.Time) bool {
	if len(weekdays) == 0 {
		return true
	}
	token, _ := normalizeWeekdayToken(t.Weekday().String())
	for _, candidate := range weekdays {
		if candidate == token {
			return true
		}
	}
	return false
}

func policyDueAt(policy UpdatePolicy, slotLocal time.Time) bool {
	minutes, err := parseTimeLocalMinutes(policy.TimeLocal)
	if err != nil {
		return false
	}
	if slotLocal.Hour()*60+slotLocal.Minute() != minutes {
		return false
	}
	switch policy.CadenceKind {
	case updatePolicyCadenceDaily:
		return true
	case updatePolicyCadenceWeekly:
		return weekdayMatchesLocal(policy.Weekdays, slotLocal)
	default:
		return false
	}
}

func nextWeekdayToken(token string) string {
	switch token {
	case "mon":
		return "tue"
	case "tue":
		return "wed"
	case "wed":
		return "thu"
	case "thu":
		return "fri"
	case "fri":
		return "sat"
	case "sat":
		return "sun"
	default:
		return "mon"
	}
}

func canonicalScheduledForUTC(slotLocal time.Time) string {
	loc := slotLocal.Location()
	if loc == nil {
		loc = time.Local
	}
	// Rebuilding the wall-clock minute through time.Date makes the repeated
	// fallback-hour slot resolve to its first occurrence, so the scheduler
	// keeps a single run key for that local minute.
	canonicalLocal := time.Date(
		slotLocal.Year(),
		slotLocal.Month(),
		slotLocal.Day(),
		slotLocal.Hour(),
		slotLocal.Minute(),
		0,
		0,
		loc,
	)
	return canonicalLocal.UTC().Format(jobTimestampLayout)
}

func blackoutApplies(slotLocal time.Time, windows []UpdatePolicyBlackoutWindow) bool {
	if len(windows) == 0 {
		return false
	}
	minutesOfDay := slotLocal.Hour()*60 + slotLocal.Minute()
	currentWeekday, _ := normalizeWeekdayToken(slotLocal.Weekday().String())
	for _, window := range windows {
		startMinutes, startErr := parseTimeLocalMinutes(window.StartTime)
		endMinutes, endErr := parseTimeLocalMinutes(window.EndTime)
		if startErr != nil || endErr != nil || startMinutes == endMinutes {
			continue
		}
		for _, weekday := range window.Weekdays {
			if startMinutes < endMinutes {
				if weekday == currentWeekday && minutesOfDay >= startMinutes && minutesOfDay < endMinutes {
					return true
				}
				continue
			}
			if weekday == currentWeekday && minutesOfDay >= startMinutes {
				return true
			}
			if nextWeekdayToken(weekday) == currentWeekday && minutesOfDay < endMinutes {
				return true
			}
		}
	}
	return false
}

func candidatePriority(policy UpdatePolicy) [3]int {
	modeRank := 99
	switch policy.ExecutionMode {
	case updatePolicyExecutionApprovalRequired:
		modeRank = 0
	case updatePolicyExecutionAutoApply:
		modeRank = 1
	case updatePolicyExecutionScanOnly:
		modeRank = 2
	}
	scopeRank := 1
	if policy.PackageScope == updatePolicyPackageScopeFull {
		scopeRank = 0
	}
	return [3]int{modeRank, scopeRank, int(policy.ID)}
}

func comparePolicyCandidates(a, b scheduledPolicyCandidate) bool {
	pa := candidatePriority(a.policy)
	pb := candidatePriority(b.policy)
	for i := 0; i < len(pa); i++ {
		if pa[i] == pb[i] {
			continue
		}
		return pa[i] < pb[i]
	}
	if a.policy.CreatedAt == b.policy.CreatedAt {
		return a.policy.ID < b.policy.ID
	}
	return a.policy.CreatedAt < b.policy.CreatedAt
}

func createSkippedPolicyRun(policy UpdatePolicy, serverName, scheduledForUTC, reason, summary string) {
	run := UpdatePolicyRun{
		PolicyID:        policy.ID,
		PolicyName:      policy.Name,
		ServerName:      serverName,
		ScheduledForUTC: scheduledForUTC,
		ExecutionMode:   policy.ExecutionMode,
		PackageScope:    policy.PackageScope,
		Status:          updatePolicyRunSkipped,
		Reason:          reason,
		Summary:         summary,
		ResultJSON:      "{}",
		FinishedAt:      jobTimestampNow(),
	}
	createdRun, inserted, err := createUpdatePolicyRun(run)
	if err != nil || !inserted {
		return
	}
	auditWithActor(
		"system",
		"",
		"schedule.run.skipped",
		"server",
		serverName,
		"ignored",
		summary,
		map[string]any{
			"policy_id":         policy.ID,
			"policy_name":       policy.Name,
			"reason":            reason,
			"scheduled_for_utc": scheduledForUTC,
			"run_id":            createdRun.ID,
		},
	)
}

func buildScheduledJobMeta(policy UpdatePolicy, scheduledForUTC string) scheduledJobMeta {
	meta := scheduledJobMeta{
		Trigger:                "scheduled",
		PolicyID:               policy.ID,
		PolicyName:             policy.Name,
		ScheduledFor:           scheduledForUTC,
		ExecutionMode:          policy.ExecutionMode,
		PackageScope:           policy.PackageScope,
		ApprovalTimeoutMinutes: policy.ApprovalTimeoutMinutes,
	}
	if policy.ExecutionMode == updatePolicyExecutionAutoApply {
		if policy.PackageScope == updatePolicyPackageScopeSecurity {
			meta.AutoApproveScope = "security"
		} else {
			meta.AutoApproveScope = "all"
		}
	}
	return meta
}

func createServerActionJobWithMeta(kind, serverName, actor, clientIP string, policy RetryPolicy, meta any) (JobRecord, error) {
	jm := currentJobManager()
	if jm == nil {
		return JobRecord{}, errors.New("job manager is not initialized")
	}
	snapshot := currentStatusSnapshot(serverName)
	initialLogs := ""
	if snapshot != nil {
		initialLogs = snapshot.Logs
	}
	return jm.CreateJob(JobCreateParams{
		Kind:            kind,
		ServerName:      serverName,
		Actor:           actor,
		ClientIP:        clientIP,
		Status:          jobStatusQueued,
		LogsText:        initialLogs,
		RetryPolicyJSON: marshalJobJSON(policy),
		MetaJSON:        marshalJobJSON(meta),
	})
}

func updatePolicyRunFromJobRecord(runID int64, job JobRecord) {
	status := updatePolicyRunRunning
	switch job.Status {
	case jobStatusQueued:
		status = updatePolicyRunQueued
	case jobStatusRunning:
		status = updatePolicyRunRunning
	case jobStatusWaitingApproval:
		status = updatePolicyRunWaitingApproval
	case jobStatusSucceeded:
		status = updatePolicyRunSucceeded
	case jobStatusFailed:
		status = updatePolicyRunFailed
	case jobStatusCancelled:
		status = updatePolicyRunCancelled
	case jobStatusInterrupted:
		status = updatePolicyRunInterrupted
	}
	update := updatePolicyRunUpdate{
		Status:    &status,
		Summary:   stringPtr(strings.TrimSpace(job.Summary)),
		JobID:     &job.ID,
		StartedAt: &job.StartedAt,
	}
	if job.FinishedAt != "" {
		update.FinishedAt = &job.FinishedAt
	}
	if strings.TrimSpace(job.MetaJSON) != "" {
		var meta scheduledJobMeta
		if err := json.Unmarshal([]byte(job.MetaJSON), &meta); err == nil && meta.Discovery != nil {
			resultJSON := marshalJobJSON(meta.Discovery)
			update.ResultJSON = &resultJSON
		}
	}
	if status == updatePolicyRunFailed || status == updatePolicyRunCancelled || status == updatePolicyRunInterrupted {
		reason := status
		update.Reason = &reason
	}
	_ = updateUpdatePolicyRun(runID, update)
}

func watchUpdatePolicyRunForJob(runID int64, jobID string) {
	startTrackedActionRunner(func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			jm := currentJobManager()
			if jm == nil {
				return
			}
			job, err := jm.GetJob(jobID)
			if err != nil {
				log.Printf("failed to read scheduled job %q for run %d: %v", jobID, runID, err)
				return
			}
			updatePolicyRunFromJobRecord(runID, job)
			switch job.Status {
			case jobStatusSucceeded, jobStatusFailed, jobStatusCancelled, jobStatusInterrupted:
				return
			}
			<-ticker.C
		}
	})
}

func loadScheduledJobBehavior(jobID string) scheduledJobBehavior {
	behavior := scheduledJobBehavior{ApprovalTimeout: 30 * time.Minute}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return behavior
	}
	jm := currentJobManager()
	if jm == nil {
		return behavior
	}
	job, err := jm.GetJob(jobID)
	if err != nil || strings.TrimSpace(job.MetaJSON) == "" {
		return behavior
	}
	var meta scheduledJobMeta
	if err := json.Unmarshal([]byte(job.MetaJSON), &meta); err != nil {
		return behavior
	}
	if meta.Trigger != "scheduled" {
		return behavior
	}
	if meta.ApprovalTimeoutMinutes > 0 {
		behavior.ApprovalTimeout = time.Duration(meta.ApprovalTimeoutMinutes) * time.Minute
	}
	if strings.TrimSpace(meta.AutoApproveScope) != "" {
		switch normalizeApprovalScope(meta.AutoApproveScope) {
		case "security":
			behavior.AutoApproveScope = "security"
		case "all":
			behavior.AutoApproveScope = "all"
		}
	}
	return behavior
}

func updateScheduledJobDiscoveryMeta(jobID string, upgradable []string, pendingUpdates []PendingUpdate) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return
	}
	jm := currentJobManager()
	if jm == nil {
		return
	}
	job, err := jm.GetJob(jobID)
	if err != nil || strings.TrimSpace(job.MetaJSON) == "" {
		return
	}
	var meta scheduledJobMeta
	if err := json.Unmarshal([]byte(job.MetaJSON), &meta); err != nil {
		return
	}
	if meta.Trigger != "scheduled" {
		return
	}
	securityCount := len(securityPackagesFromPendingUpdates(pendingUpdates))
	meta.Discovery = &scheduledJobDiscovery{
		PendingPackageCount:  len(upgradable),
		SecurityPackageCount: securityCount,
		Upgradable:           append([]string(nil), upgradable...),
		PendingUpdates:       clonePendingUpdates(pendingUpdates),
	}
	metaJSON := marshalJobJSON(meta)
	if err := jm.UpdateJobWithoutRuntimeSync(jobID, JobUpdate{MetaJSON: &metaJSON}); err != nil {
		log.Printf("failed to persist scheduled discovery meta for job %q: %v", jobID, err)
	}
}

func executeScheduledPolicyRun(run UpdatePolicyRun, policy UpdatePolicy, server Server) {
	switch policy.ExecutionMode {
	case updatePolicyExecutionScanOnly:
		runScheduledScanPolicy(run, policy, server)
	default:
		runScheduledUpdatePolicy(run, policy, server)
	}
}

func runScheduledUpdatePolicy(run UpdatePolicyRun, policy UpdatePolicy, server Server) {
	preStartStatus := currentStatusSnapshot(server.Name)
	serverForRun, err := beginServerAction(server.Name, "updating")
	if err != nil {
		status := updatePolicyRunFailed
		reason := updatePolicyRunReasonMissing
		summary := "Server unavailable for scheduled update"
		if errors.Is(err, errActionInProgress) {
			status = updatePolicyRunSkipped
			reason = updatePolicyRunReasonBusy
			summary = "Server busy; scheduled update skipped"
		}
		finishedAt := jobTimestampNow()
		_ = updateUpdatePolicyRun(run.ID, updatePolicyRunUpdate{
			Status:     &status,
			Reason:     &reason,
			Summary:    &summary,
			FinishedAt: &finishedAt,
		})
		auditWithActor("system", "", "schedule.run."+status, "server", server.Name, status, summary, map[string]any{
			"policy_id":         policy.ID,
			"policy_name":       policy.Name,
			"scheduled_for_utc": run.ScheduledForUTC,
		})
		return
	}
	meta := buildScheduledJobMeta(policy, run.ScheduledForUTC)
	job, err := createServerActionJobWithMeta(jobKindUpdate, server.Name, "system", "", loadRetryPolicyFromEnv(), meta)
	if err != nil {
		restoreStatusSnapshot(server.Name, preStartStatus)
		status := updatePolicyRunFailed
		reason := updatePolicyRunReasonPersistence
		summary := "Failed to create scheduled update job"
		auditAction := "schedule.run.failed"
		auditStatus := "failure"
		if errors.Is(err, errMaintenanceModeActive) {
			status = updatePolicyRunSkipped
			reason = updatePolicyRunReasonMaintenance
			summary = "Maintenance mode active; scheduled update skipped"
			auditAction = "schedule.run.skipped"
			auditStatus = "skipped"
		}
		finishedAt := jobTimestampNow()
		_ = updateUpdatePolicyRun(run.ID, updatePolicyRunUpdate{
			Status:     &status,
			Reason:     &reason,
			Summary:    &summary,
			FinishedAt: &finishedAt,
		})
		auditWithActor("system", "", auditAction, "server", server.Name, auditStatus, summary, map[string]any{
			"policy_id":         policy.ID,
			"policy_name":       policy.Name,
			"scheduled_for_utc": run.ScheduledForUTC,
			"error":             err.Error(),
		})
		return
	}
	runningStatus := updatePolicyRunRunning
	startedAt := jobTimestampNow()
	summary := "Scheduled update started"
	_ = updateUpdatePolicyRun(run.ID, updatePolicyRunUpdate{
		Status:    &runningStatus,
		Summary:   &summary,
		JobID:     &job.ID,
		StartedAt: &startedAt,
	})
	auditWithActor("system", "", "schedule.run.started", "server", server.Name, "started", summary, map[string]any{
		"policy_id":         policy.ID,
		"policy_name":       policy.Name,
		"scheduled_for_utc": run.ScheduledForUTC,
		"job_id":            job.ID,
		"execution_mode":    policy.ExecutionMode,
		"package_scope":     policy.PackageScope,
	})
	startUpdateRunner(serverForRun, "system", "", loadRetryPolicyFromEnv(), job.ID)
	watchUpdatePolicyRunForJob(run.ID, job.ID)
}

func runScheduledScanPolicy(run UpdatePolicyRun, policy UpdatePolicy, server Server) {
	preStartStatus := currentStatusSnapshot(server.Name)
	if _, err := beginServerAction(server.Name, "updating"); err != nil {
		status := updatePolicyRunFailed
		reason := updatePolicyRunReasonMissing
		summary := "Server unavailable for scheduled scan"
		if errors.Is(err, errActionInProgress) {
			status = updatePolicyRunSkipped
			reason = updatePolicyRunReasonBusy
			summary = "Server busy; scheduled scan skipped"
		}
		finishedAt := jobTimestampNow()
		_ = updateUpdatePolicyRun(run.ID, updatePolicyRunUpdate{
			Status:     &status,
			Reason:     &reason,
			Summary:    &summary,
			FinishedAt: &finishedAt,
		})
		auditWithActor("system", "", "schedule.run."+status, "server", server.Name, status, summary, map[string]any{
			"policy_id":         policy.ID,
			"policy_name":       policy.Name,
			"scheduled_for_utc": run.ScheduledForUTC,
		})
		return
	}

	retryPolicy := loadRetryPolicyFromEnv()
	meta := buildScheduledJobMeta(policy, run.ScheduledForUTC)
	jm := currentJobManager()
	if jm == nil {
		status := updatePolicyRunFailed
		reason := updatePolicyRunReasonPersistence
		summary := "Job manager unavailable"
		finishedAt := jobTimestampNow()
		_ = updateUpdatePolicyRun(run.ID, updatePolicyRunUpdate{
			Status:     &status,
			Reason:     &reason,
			Summary:    &summary,
			FinishedAt: &finishedAt,
		})
		auditWithActor("system", "", "schedule.run.failed", "server", server.Name, "failure", summary, map[string]any{
			"policy_id":         policy.ID,
			"policy_name":       policy.Name,
			"scheduled_for_utc": run.ScheduledForUTC,
			"error":             "job manager unavailable",
		})
		restoreStatusSnapshot(server.Name, preStartStatus)
		return
	}
	job, err := jm.CreateJob(JobCreateParams{
		Kind:            jobKindScheduledScan,
		ServerName:      server.Name,
		Actor:           "system",
		Status:          jobStatusQueued,
		RetryPolicyJSON: marshalJobJSON(retryPolicy),
		MetaJSON:        marshalJobJSON(meta),
		Summary:         "Scheduled scan queued",
	})
	if err != nil {
		status := updatePolicyRunFailed
		reason := updatePolicyRunReasonPersistence
		summary := "Failed to create scheduled scan job"
		auditAction := "schedule.run.failed"
		auditStatus := "failure"
		if errors.Is(err, errMaintenanceModeActive) {
			status = updatePolicyRunSkipped
			reason = updatePolicyRunReasonMaintenance
			summary = "Maintenance mode active; scheduled scan skipped"
			auditAction = "schedule.run.skipped"
			auditStatus = "skipped"
		}
		finishedAt := jobTimestampNow()
		_ = updateUpdatePolicyRun(run.ID, updatePolicyRunUpdate{
			Status:     &status,
			Reason:     &reason,
			Summary:    &summary,
			FinishedAt: &finishedAt,
		})
		auditWithActor("system", "", auditAction, "server", server.Name, auditStatus, summary, map[string]any{
			"policy_id":         policy.ID,
			"policy_name":       policy.Name,
			"scheduled_for_utc": run.ScheduledForUTC,
			"error":             err.Error(),
		})
		restoreStatusSnapshot(server.Name, preStartStatus)
		return
	}
	runningStatus := updatePolicyRunRunning
	startedAt := jobTimestampNow()
	summary := "Scheduled scan started"
	_ = updateUpdatePolicyRun(run.ID, updatePolicyRunUpdate{
		Status:    &runningStatus,
		Summary:   &summary,
		JobID:     &job.ID,
		StartedAt: &startedAt,
	})
	auditWithActor("system", "", "schedule.run.started", "server", server.Name, "started", summary, map[string]any{
		"policy_id":         policy.ID,
		"policy_name":       policy.Name,
		"scheduled_for_utc": run.ScheduledForUTC,
		"job_id":            job.ID,
		"execution_mode":    policy.ExecutionMode,
		"package_scope":     policy.PackageScope,
	})

	startJobRunner(job.ID, func() {
		defer restoreStatusSnapshot(server.Name, preStartStatus)
		runScheduledScanJob(job.ID, run.ID, run.ScheduledForUTC, server, policy, retryPolicy)
	})
}

func runScheduledScanJob(jobID string, runID int64, scheduledForUTC string, server Server, policy UpdatePolicy, retryPolicy RetryPolicy) {
	jm := currentJobManager()
	setFailure := func(summary string, err error, phase string, logs string) {
		if jm != nil && strings.TrimSpace(jobID) != "" {
			status := jobStatusFailed
			jobPhase := phase
			finishedAt := jobTimestampNow()
			errorClass := "permanent"
			_ = jm.UpdateJobWithoutRuntimeSync(jobID, JobUpdate{
				Status:     &status,
				Phase:      &jobPhase,
				Summary:    &summary,
				LogsText:   &logs,
				ErrorClass: &errorClass,
				FinishedAt: &finishedAt,
			})
		}
		runStatus := updatePolicyRunFailed
		reason := "failed"
		finishedAt := jobTimestampNow()
		_ = updateUpdatePolicyRun(runID, updatePolicyRunUpdate{
			Status:     &runStatus,
			Reason:     &reason,
			Summary:    &summary,
			FinishedAt: &finishedAt,
		})
		meta := map[string]any{
			"policy_id":      policy.ID,
			"policy_name":    policy.Name,
			"execution_mode": policy.ExecutionMode,
			"package_scope":  policy.PackageScope,
		}
		if err != nil {
			meta["error"] = err.Error()
		}
		auditWithActor("system", "", "schedule.run.failed", "server", server.Name, "failure", summary, meta)
	}

	authMethods, err := buildAuthMethods(server)
	if err != nil {
		setFailure("Scheduled scan auth setup failed", err, jobPhaseDial, "")
		return
	}
	hostKeyCallback, err := getHostKeyCallback()
	if err != nil {
		setFailure("Scheduled scan host key setup failed", err, jobPhaseDial, "")
		return
	}
	config := &ssh.ClientConfig{
		User:            server.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}
	client, err := dialSSHWithRetry(server, config, retryPolicy, "scheduled_scan.ssh_dial", nil)
	if err != nil {
		setFailure("Scheduled scan SSH connection failed", err, jobPhaseDial, "")
		return
	}
	defer func() { _ = client.Close() }()

	logs := "Starting scheduled package scan..."
	if jm != nil {
		phase := jobPhasePrechecks
		summary := "Running pre-checks"
		_ = jm.UpdateJobWithoutRuntimeSync(jobID, JobUpdate{
			Phase:    &phase,
			Summary:  &summary,
			LogsText: &logs,
		})
	}
	precheckSummary := runUpdatePrechecks(client)
	for _, result := range precheckSummary.Results {
		state := "PASS"
		if !result.Passed {
			state = "FAIL"
		}
		line := fmt.Sprintf("\nPre-check %s [%s]: %s", result.Name, state, result.Details)
		if trimmed := strings.TrimSpace(result.Output); trimmed != "" {
			line += fmt.Sprintf(" Output: %s", trimmed)
		}
		logs += line
	}
	if !precheckSummary.AllPassed {
		setFailure(fmt.Sprintf("Scheduled scan pre-check failed (%s)", precheckSummary.FailedCheck), nil, jobPhasePrechecks, logs)
		return
	}

	if jm != nil {
		phase := jobPhaseAptUpdate
		summary := "Running apt update"
		_ = jm.UpdateJobWithoutRuntimeSync(jobID, JobUpdate{
			Phase:    &phase,
			Summary:  &summary,
			LogsText: &logs,
		})
	}
	var stdout, stderr string
	err = runSSHOperationWithRetry(
		server,
		config,
		&client,
		retryPolicy,
		"scheduled_scan.apt_update",
		"\napt update attempt %d/%d failed: %v; retrying in %s",
		new(int),
		func() error {
			var runErr error
			stdout, stderr, runErr = runSSHCommandWithTimeout(client, aptUpdateCmd, nil, loadSSHCommandTimeoutFromEnv())
			return markRetryableFromOutput(runErr, stdout+"\n"+stderr)
		},
	)
	logs += "\n" + stdout + stderr
	if err != nil {
		setFailure("Scheduled scan apt update failed", err, jobPhaseAptUpdate, logs)
		return
	}

	var pendingUpdates []PendingUpdate
	var upgradable []string
	err = runSSHOperationWithRetry(
		server,
		config,
		&client,
		retryPolicy,
		"scheduled_scan.list_upgradable",
		"\nlist upgradable attempt %d/%d failed: %v; retrying in %s",
		new(int),
		func() error {
			var listErr error
			pendingUpdates, upgradable, listErr = getUpgradable(client, loadSSHCommandTimeoutFromEnv())
			return listErr
		},
	)
	if err != nil {
		setFailure("Scheduled scan package discovery failed", err, jobPhaseAptUpdate, logs)
		return
	}

	pendingUpdates = preparePendingUpdatesForCVE(pendingUpdates)
	for i := range pendingUpdates {
		if pendingUpdates[i].CVEState != "pending" {
			continue
		}
		cves, lookupErr := queryPackageCVEs(client, pendingUpdates[i].Package)
		if lookupErr != nil {
			pendingUpdates[i].CVEState = "unavailable"
			pendingUpdates[i].CVEs = []string{}
			continue
		}
		pendingUpdates[i].CVEState = "ready"
		pendingUpdates[i].CVEs = append([]string(nil), cves...)
	}
	sortPendingUpdates(pendingUpdates)
	result := scheduledJobDiscovery{
		PendingPackageCount:  len(upgradable),
		SecurityPackageCount: len(securityPackagesFromPendingUpdates(pendingUpdates)),
		Upgradable:           append([]string(nil), upgradable...),
		PendingUpdates:       clonePendingUpdates(pendingUpdates),
	}
	resultJSON := marshalJobJSON(result)
	finalSummary := "Scheduled scan completed"
	if len(upgradable) == 0 {
		finalSummary = "Scheduled scan completed: no pending updates"
	}
	if jm != nil {
		status := jobStatusSucceeded
		phase := jobPhaseComplete
		meta := buildScheduledJobMeta(policy, scheduledForUTC)
		meta.Discovery = &result
		metaJSON := marshalJobJSON(meta)
		finishedAt := jobTimestampNow()
		_ = jm.UpdateJobWithoutRuntimeSync(jobID, JobUpdate{
			Status:     &status,
			Phase:      &phase,
			Summary:    &finalSummary,
			LogsText:   &logs,
			MetaJSON:   &metaJSON,
			FinishedAt: &finishedAt,
		})
	}
	runStatus := updatePolicyRunSucceeded
	finishedAt := jobTimestampNow()
	_ = updateUpdatePolicyRun(runID, updatePolicyRunUpdate{
		Status:     &runStatus,
		Summary:    &finalSummary,
		ResultJSON: &resultJSON,
		FinishedAt: &finishedAt,
	})
	auditWithActor("system", "", "schedule.run.completed", "server", server.Name, "success", finalSummary, map[string]any{
		"policy_id":              policy.ID,
		"policy_name":            policy.Name,
		"pending_package_count":  result.PendingPackageCount,
		"security_package_count": result.SecurityPackageCount,
	})
}

func processDueUpdatePolicies(now time.Time) error {
	updatePolicyTickMu.Lock()
	defer updatePolicyTickMu.Unlock()

	policies, err := listUpdatePolicies()
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return nil
	}
	overrides, err := loadAllUpdatePolicyOverrides()
	if err != nil {
		return err
	}
	globalBlackouts, err := loadGlobalUpdatePolicyBlackouts()
	if err != nil {
		return err
	}
	slotLocal := now.In(time.Local).Truncate(time.Minute)
	scheduledForUTC := canonicalScheduledForUTC(slotLocal)
	serversSnapshot := snapshotServers()

	candidatesByServer := make(map[string][]scheduledPolicyCandidate)
	for _, policy := range policies {
		if !policy.Enabled || !policyDueAt(policy, slotLocal) {
			continue
		}
		for _, server := range serversSnapshot {
			if !policyMatchesServer(policy, server, overrides) {
				continue
			}
			if blackoutApplies(slotLocal, globalBlackouts) || blackoutApplies(slotLocal, policy.PolicyBlackouts) {
				createSkippedPolicyRun(policy, server.Name, scheduledForUTC, updatePolicyRunReasonBlackout, "Scheduled run skipped due to blackout window")
				continue
			}
			candidatesByServer[server.Name] = append(candidatesByServer[server.Name], scheduledPolicyCandidate{
				policy:          policy,
				server:          server,
				scheduledForUTC: scheduledForUTC,
			})
		}
	}

	var queueErrs []error
	for serverName, candidates := range candidatesByServer {
		if len(candidates) == 0 {
			continue
		}
		sort.Slice(candidates, func(i, j int) bool {
			return comparePolicyCandidates(candidates[i], candidates[j])
		})
		winner := candidates[0]
		for _, skipped := range candidates[1:] {
			createSkippedPolicyRun(skipped.policy, serverName, skipped.scheduledForUTC, updatePolicyRunReasonSuperseded, "Scheduled run superseded by higher-priority policy")
		}

		runtimeStatus := currentStatusSnapshot(serverName)
		if runtimeStatus == nil {
			createSkippedPolicyRun(winner.policy, serverName, winner.scheduledForUTC, updatePolicyRunReasonMissing, "Scheduled run skipped because the server was missing")
			continue
		}
		if statusInProgress(runtimeStatus.Status) {
			createSkippedPolicyRun(winner.policy, serverName, winner.scheduledForUTC, updatePolicyRunReasonBusy, "Scheduled run skipped because the server is busy")
			continue
		}

		run, inserted, err := createUpdatePolicyRun(UpdatePolicyRun{
			PolicyID:        winner.policy.ID,
			PolicyName:      winner.policy.Name,
			ServerName:      serverName,
			ScheduledForUTC: winner.scheduledForUTC,
			ExecutionMode:   winner.policy.ExecutionMode,
			PackageScope:    winner.policy.PackageScope,
			Status:          updatePolicyRunQueued,
			Summary:         "Scheduled run queued",
			ResultJSON:      "{}",
		})
		if err != nil {
			queueErr := fmt.Errorf(
				"queue scheduled run failed: policy_id=%d policy_name=%q server=%q scheduled_for_utc=%q: %w",
				winner.policy.ID,
				winner.policy.Name,
				serverName,
				winner.scheduledForUTC,
				err,
			)
			log.Printf("processDueUpdatePolicies: %v", queueErr)
			queueErrs = append(queueErrs, queueErr)
			continue
		}
		if !inserted {
			continue
		}
		executeScheduledPolicyRun(run, winner.policy, winner.server)
	}
	if len(queueErrs) > 0 {
		return fmt.Errorf("scheduled policy queue encountered %d error(s): %w", len(queueErrs), errors.Join(queueErrs...))
	}
	return nil
}

func startUpdatePolicyScheduler(ctx context.Context) {
	updatePolicySchedulerOnce.Do(func() {
		if err := markInterruptedUpdatePolicyRuns(); err != nil {
			log.Printf("failed to mark interrupted policy runs: %v", err)
		}
		if err := processDueUpdatePolicies(time.Now()); err != nil {
			log.Printf("scheduled policy tick failed: %v", err)
		}
		go func() {
			ticker := time.NewTicker(updatePolicyTickInterval)
			defer ticker.Stop()
			for {
				select {
				case tick := <-ticker.C:
					if err := processDueUpdatePolicies(tick); err != nil {
						log.Printf("scheduled policy tick failed: %v", err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	})
}

func handleUpdatePoliciesList(c *gin.Context) {
	policies, err := listUpdatePolicies()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load update policies"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":    enrichPoliciesWithMatches(policies),
		"timezone": currentAppTimezoneName(),
	})
}

func handleUpdatePolicyCreate(c *gin.Context) {
	var policy UpdatePolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		audit(c, "update_policy.create", "update_policy", "-", "failure", "Invalid request payload", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	created, err := createUpdatePolicy(policy)
	if err != nil {
		audit(c, "update_policy.create", "update_policy", policy.Name, "failure", "Failed to create policy", map[string]any{"error": err.Error()})
		statusCode := http.StatusInternalServerError
		if isUpdatePolicyValidationError(err) {
			statusCode = http.StatusBadRequest
		}
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}
	audit(c, "update_policy.create", "update_policy", created.Name, "success", "Update policy created", map[string]any{
		"policy_id":      created.ID,
		"execution_mode": created.ExecutionMode,
		"package_scope":  created.PackageScope,
		"target_tag":     created.TargetTag,
		"cadence_kind":   created.CadenceKind,
		"time_local":     created.TimeLocal,
	})
	c.JSON(http.StatusCreated, created)
}

func handleUpdatePolicyUpdate(c *gin.Context) {
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}
	var policy UpdatePolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		audit(c, "update_policy.update", "update_policy", c.Param("id"), "failure", "Invalid request payload", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated, err := updateUpdatePolicy(id, policy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		audit(c, "update_policy.update", "update_policy", c.Param("id"), "failure", "Failed to update policy", map[string]any{"error": err.Error()})
		statusCode := http.StatusInternalServerError
		if isUpdatePolicyValidationError(err) {
			statusCode = http.StatusBadRequest
		}
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}
	audit(c, "update_policy.update", "update_policy", updated.Name, "success", "Update policy updated", map[string]any{"policy_id": updated.ID})
	c.JSON(http.StatusOK, updated)
}

func handleUpdatePolicyDelete(c *gin.Context) {
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}
	policy, _ := getUpdatePolicy(id)
	if err := deleteUpdatePolicy(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		audit(c, "update_policy.delete", "update_policy", c.Param("id"), "failure", "Failed to delete policy", map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete policy"})
		return
	}
	audit(c, "update_policy.delete", "update_policy", policy.Name, "success", "Update policy deleted", map[string]any{"policy_id": id})
	c.JSON(http.StatusOK, gin.H{"message": "policy deleted"})
}

func handleUpdatePolicyRuns(c *gin.Context) {
	limit, _ := strconv.Atoi(strings.TrimSpace(c.DefaultQuery("limit", "100")))
	runs, err := listUpdatePolicyRuns(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load policy runs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":    runs,
		"timezone": currentAppTimezoneName(),
	})
}

func handleUpdatePolicyOverrides(c *gin.Context) {
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}
	policy, err := getUpdatePolicy(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	items, err := listUpdatePolicyOverrides(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load overrides"})
		return
	}
	for i := range items {
		items[i].PolicyName = policy.Name
		items[i].TargetTag = policy.TargetTag
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func handleUpdatePolicyOverrideUpsert(c *gin.Context) {
	id, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
		return
	}
	serverName := strings.TrimSpace(c.Param("server"))
	if serverName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "server name is required"})
		return
	}
	if _, err := getUpdatePolicy(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}
	if !serverExistsByName(serverName) {
		audit(c, "update_policy.override", "server", serverName, "failure", "Server not found", map[string]any{"policy_id": id})
		c.JSON(http.StatusNotFound, gin.H{"error": "server not found"})
		return
	}
	var req struct {
		Disabled bool `json:"disabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		audit(c, "update_policy.override", "server", serverName, "failure", "Invalid request payload", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	override, err := setUpdatePolicyOverride(id, serverName, req.Disabled)
	if err != nil {
		audit(c, "update_policy.override", "server", serverName, "failure", "Failed to save override", map[string]any{"error": err.Error(), "policy_id": id})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save override"})
		return
	}
	status := "enabled"
	if req.Disabled {
		status = "disabled"
	}
	audit(c, "update_policy.override", "server", serverName, "success", "Policy override updated", map[string]any{"policy_id": id, "override_state": status})
	c.JSON(http.StatusOK, override)
}

func handleUpdatePolicySettingsStatus(c *gin.Context) {
	windows, err := loadGlobalUpdatePolicyBlackouts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load scheduled update settings"})
		return
	}
	c.JSON(http.StatusOK, UpdatePolicySettingsResponse{
		Timezone:        currentAppTimezoneName(),
		GlobalBlackouts: windows,
	})
}

func handleUpdatePolicySettingsUpdate(c *gin.Context) {
	var req UpdatePolicySettingsResponse
	if err := c.ShouldBindJSON(&req); err != nil {
		audit(c, "update_policy.settings", "update_policy", "global", "failure", "Invalid request payload", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	normalizedBlackouts, err := saveGlobalUpdatePolicyBlackouts(req.GlobalBlackouts)
	if err != nil {
		audit(c, "update_policy.settings", "update_policy", "global", "failure", "Failed to save scheduled update settings", map[string]any{"error": err.Error()})
		statusCode := http.StatusInternalServerError
		if isUpdatePolicyValidationError(err) {
			statusCode = http.StatusBadRequest
		}
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}
	audit(c, "update_policy.settings", "update_policy", "global", "success", "Scheduled update settings saved", map[string]any{"global_blackout_count": len(normalizedBlackouts)})
	c.JSON(http.StatusOK, UpdatePolicySettingsResponse{
		Timezone:        currentAppTimezoneName(),
		GlobalBlackouts: normalizedBlackouts,
	})
}
