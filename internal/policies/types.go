package policies

import "time"

const (
	ExecutionScanOnly         = "scan_only"
	ExecutionApprovalRequired = "approval_required"
	ExecutionAutoApply        = "auto_apply"

	PackageScopeSecurity = "security"
	PackageScopeFull     = "full"

	CadenceDaily  = "daily"
	CadenceWeekly = "weekly"

	RunQueued          = "queued"
	RunRunning         = "running"
	RunWaitingApproval = "waiting_approval"
	RunSucceeded       = "succeeded"
	RunFailed          = "failed"
	RunSkipped         = "skipped"
	RunCancelled       = "cancelled"
	RunInterrupted     = "interrupted"

	RunReasonBlackout    = "blackout"
	RunReasonBusy        = "busy"
	RunReasonSuperseded  = "superseded"
	RunReasonRestart     = "restart"
	RunReasonNoMatch     = "no_match"
	RunReasonMissing     = "missing"
	RunReasonMaintenance = "maintenance"
	RunReasonPersistence = "persistence"

	GlobalBlackoutsSetting        = "update_policy_global_blackouts"
	DefaultApprovalTimeoutMinutes = 720
	DefaultRunsLimit              = 100
	MaxRunsLimit                  = 200
	DefaultSchedulerTickInterval  = time.Minute
	DefaultTimestampLayout        = "2006-01-02T15:04:05.000000000Z"
)

type BlackoutWindow struct {
	Weekdays  []string `json:"weekdays"`
	StartTime string   `json:"start_time"`
	EndTime   string   `json:"end_time"`
}

type Policy struct {
	ID                     int64            `json:"id"`
	Name                   string           `json:"name"`
	Enabled                bool             `json:"enabled"`
	TargetTag              string           `json:"target_tag"`
	IncludeTags            []string         `json:"include_tags"`
	ExcludeTags            []string         `json:"exclude_tags"`
	TargetServers          []string         `json:"target_servers"`
	PackageScope           string           `json:"package_scope"`
	ExecutionMode          string           `json:"execution_mode"`
	CadenceKind            string           `json:"cadence_kind"`
	TimeLocal              string           `json:"time_local"`
	Weekdays               []string         `json:"weekdays"`
	ApprovalTimeoutMinutes int              `json:"approval_timeout_minutes"`
	PolicyBlackouts        []BlackoutWindow `json:"policy_blackouts"`
	CreatedAt              string           `json:"created_at"`
	UpdatedAt              string           `json:"updated_at"`
	MatchedServers         []string         `json:"matched_servers,omitempty"`
}

type Override struct {
	PolicyID    int64  `json:"policy_id"`
	ServerName  string `json:"server_name"`
	Disabled    bool   `json:"disabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	PolicyName  string `json:"policy_name,omitempty"`
	TargetTag   string `json:"target_tag,omitempty"`
	ServerMatch bool   `json:"server_match,omitempty"`
}

type Run struct {
	ID                  int64  `json:"id"`
	PolicyID            int64  `json:"policy_id"`
	PolicyName          string `json:"policy_name"`
	ServerName          string `json:"server_name"`
	ScheduledForUTC     string `json:"scheduled_for_utc"`
	ScheduledForDisplay string `json:"scheduled_for_display,omitempty"`
	ExecutionMode       string `json:"execution_mode"`
	PackageScope        string `json:"package_scope"`
	Status              string `json:"status"`
	Reason              string `json:"reason"`
	Summary             string `json:"summary"`
	JobID               string `json:"job_id"`
	ResultJSON          string `json:"result_json"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
	StartedAt           string `json:"started_at"`
	FinishedAt          string `json:"finished_at"`
}

type SettingsResponse struct {
	Timezone         string           `json:"timezone"`
	ResolvedTimezone string           `json:"resolved_timezone"`
	GlobalBlackouts  []BlackoutWindow `json:"global_blackouts"`
}

type RunUpdate struct {
	Status     *string
	Reason     *string
	Summary    *string
	JobID      *string
	ResultJSON *string
	StartedAt  *string
	FinishedAt *string
}
