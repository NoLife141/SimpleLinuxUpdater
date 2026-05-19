package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	policypkg "debian-updater/internal/policies"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

const (
	updatePolicyExecutionScanOnly         = policypkg.ExecutionScanOnly
	updatePolicyExecutionApprovalRequired = policypkg.ExecutionApprovalRequired
	updatePolicyExecutionAutoApply        = policypkg.ExecutionAutoApply

	updatePolicyPackageScopeSecurity = policypkg.PackageScopeSecurity
	updatePolicyPackageScopeFull     = policypkg.PackageScopeFull

	updatePolicyCadenceDaily  = policypkg.CadenceDaily
	updatePolicyCadenceWeekly = policypkg.CadenceWeekly

	updatePolicyRunQueued          = policypkg.RunQueued
	updatePolicyRunRunning         = policypkg.RunRunning
	updatePolicyRunWaitingApproval = policypkg.RunWaitingApproval
	updatePolicyRunSucceeded       = policypkg.RunSucceeded
	updatePolicyRunFailed          = policypkg.RunFailed
	updatePolicyRunSkipped         = policypkg.RunSkipped
	updatePolicyRunCancelled       = policypkg.RunCancelled
	updatePolicyRunInterrupted     = policypkg.RunInterrupted

	updatePolicyRunReasonBlackout    = policypkg.RunReasonBlackout
	updatePolicyRunReasonBusy        = policypkg.RunReasonBusy
	updatePolicyRunReasonSuperseded  = policypkg.RunReasonSuperseded
	updatePolicyRunReasonRestart     = policypkg.RunReasonRestart
	updatePolicyRunReasonNoMatch     = policypkg.RunReasonNoMatch
	updatePolicyRunReasonMissing     = policypkg.RunReasonMissing
	updatePolicyRunReasonMaintenance = policypkg.RunReasonMaintenance
	updatePolicyRunReasonPersistence = policypkg.RunReasonPersistence

	updatePolicyGlobalBlackoutsSetting     = policypkg.GlobalBlackoutsSetting
	defaultScheduledApprovalTimeoutMinutes = policypkg.DefaultApprovalTimeoutMinutes
	defaultUpdatePolicyRunsLimit           = policypkg.DefaultRunsLimit
	maxUpdatePolicyRunsLimit               = policypkg.MaxRunsLimit
	updatePolicyTickInterval               = policypkg.DefaultSchedulerTickInterval
)

var errUpdatePolicyValidation = errors.New("update policy validation")

func wrapUpdatePolicyValidationError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", errUpdatePolicyValidation, err)
}

func isUpdatePolicyValidationError(err error) bool {
	return errors.Is(err, errUpdatePolicyValidation)
}

type UpdatePolicyBlackoutWindow = policypkg.BlackoutWindow
type UpdatePolicy = policypkg.Policy
type UpdatePolicyOverride = policypkg.Override
type UpdatePolicyRun = policypkg.Run
type UpdatePolicySettingsResponse = policypkg.SettingsResponse
type updatePolicyRunUpdate = policypkg.RunUpdate

type scheduledPolicyCandidate struct {
	policy          UpdatePolicy
	server          Server
	scheduledForUTC string
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

func defaultPolicyRepository() *policypkg.SQLiteRepository {
	return policypkg.NewSQLiteRepository(policypkg.SQLiteRepositoryDeps{
		DB:          getDB,
		NowString:   jobTimestampNow,
		MarshalJSON: marshalJobJSON,
	})
}

func ensureUpdatePolicySchema(db *sql.DB) error {
	return policypkg.EnsureSchema(db)
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

func loadGlobalUpdatePolicyBlackouts() ([]UpdatePolicyBlackoutWindow, error) {
	return defaultPolicyRepository().LoadGlobalBlackouts()
}

func saveGlobalUpdatePolicyBlackouts(windows []UpdatePolicyBlackoutWindow) ([]UpdatePolicyBlackoutWindow, error) {
	normalized, err := policypkg.NormalizeBlackouts(windows)
	if err != nil {
		return nil, wrapUpdatePolicyValidationError(err)
	}
	if err := upsertSettingValue(updatePolicyGlobalBlackoutsSetting, marshalJobJSON(normalized)); err != nil {
		return nil, err
	}
	return normalized, nil
}

func parseTimeLocalMinutes(raw string) (int, error) {
	return policypkg.ParseTimeLocalMinutes(raw)
}

//lint:ignore U1000 compatibility wrapper retained for transitional policy call sites.
func normalizeUpdatePolicy(policy *UpdatePolicy) error {
	return defaultPolicyService().NormalizePolicy(policy)
}

func listUpdatePolicies() ([]UpdatePolicy, error) {
	return defaultPolicyRepository().ListPolicies()
}

func getUpdatePolicy(id int64) (UpdatePolicy, error) {
	return defaultPolicyRepository().GetPolicy(id)
}

func createUpdatePolicy(policy UpdatePolicy) (UpdatePolicy, error) {
	return createUpdatePolicyWithService(defaultPolicyService(), policy)
}

func createUpdatePolicyWithService(service *PolicyService, policy UpdatePolicy) (UpdatePolicy, error) {
	if service == nil {
		service = defaultPolicyService()
	}
	if err := service.NormalizePolicy(&policy); err != nil {
		return UpdatePolicy{}, wrapUpdatePolicyValidationError(err)
	}
	return defaultPolicyRepository().CreatePolicy(policy)
}

//lint:ignore U1000 compatibility wrapper retained for transitional policy call sites.
func updateUpdatePolicy(id int64, policy UpdatePolicy) (UpdatePolicy, error) {
	return updateUpdatePolicyWithService(defaultPolicyService(), id, policy)
}

func updateUpdatePolicyWithService(service *PolicyService, id int64, policy UpdatePolicy) (UpdatePolicy, error) {
	if id <= 0 {
		return UpdatePolicy{}, sql.ErrNoRows
	}
	policy.ID = id
	if service == nil {
		service = defaultPolicyService()
	}
	if err := service.NormalizePolicy(&policy); err != nil {
		return UpdatePolicy{}, wrapUpdatePolicyValidationError(err)
	}
	return defaultPolicyRepository().UpdatePolicy(id, policy)
}

func deleteUpdatePolicy(id int64) error {
	return defaultPolicyRepository().DeletePolicy(id)
}

func listUpdatePolicyOverrides(policyID int64) ([]UpdatePolicyOverride, error) {
	return defaultPolicyRepository().ListOverrides(policyID)
}

func loadAllUpdatePolicyOverrides() (map[int64]map[string]bool, error) {
	return defaultPolicyRepository().LoadAllOverrides()
}

func setUpdatePolicyOverride(policyID int64, serverName string, disabled bool) (UpdatePolicyOverride, error) {
	return defaultPolicyRepository().SetOverride(policyID, serverName, disabled)
}

func renameUpdatePolicyOverridesServerTx(tx *sql.Tx, oldServerName, newServerName string) error {
	return defaultPolicyRepository().RenameOverridesServerTx(tx, oldServerName, newServerName)
}

func renameUpdatePolicyTargetServersTx(tx *sql.Tx, oldServerName, newServerName string) error {
	return defaultPolicyRepository().RenameTargetServersTx(tx, oldServerName, newServerName)
}

func pruneUpdatePolicyOverridesForServersTx(tx *sql.Tx, activeServers []Server) error {
	return defaultPolicyRepository().PruneOverridesForServersTx(tx, activeServers)
}

func createUpdatePolicyRun(run UpdatePolicyRun) (UpdatePolicyRun, bool, error) {
	return defaultPolicyRepository().CreateRun(run)
}

func getUpdatePolicyRun(id int64) (UpdatePolicyRun, error) {
	return defaultPolicyRepository().GetRun(id)
}

func updateUpdatePolicyRun(id int64, update updatePolicyRunUpdate) error {
	return defaultPolicyRepository().UpdateRun(id, update)
}

func listUpdatePolicyRuns(limit int) ([]UpdatePolicyRun, error) {
	return defaultPolicyRepository().ListRuns(limit)
}

func markInterruptedUpdatePolicyRuns() error {
	return defaultPolicyRepository().MarkInterruptedRuns()
}

func boolToInt(v bool) int {
	return policypkg.BoolToInt(v)
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
	return defaultPolicyService().PolicyMatchesServer(policy, server, PolicyMatchContext{Overrides: overrides})
}

//lint:ignore U1000 compatibility wrapper retained for transitional policy call sites.
func enrichPoliciesWithMatches(policies []UpdatePolicy) []UpdatePolicy {
	return enrichPoliciesWithMatchesUsing(defaultPolicyService(), policies)
}

func enrichPoliciesWithMatchesUsing(service *PolicyService, policies []UpdatePolicy) []UpdatePolicy {
	if service == nil {
		service = defaultPolicyService()
	}
	return service.EnrichPoliciesWithMatches(policies)
}

func policyDueAt(policy UpdatePolicy, slotLocal time.Time) bool {
	return defaultPolicyService().PolicyDueAt(policy, slotLocal)
}

func canonicalScheduledForUTC(slotLocal time.Time) string {
	return policypkg.CanonicalScheduledForUTC(slotLocal, jobTimestampLayout, currentAppLocation)
}

func blackoutApplies(slotLocal time.Time, windows []UpdatePolicyBlackoutWindow) bool {
	return defaultPolicyService().BlackoutApplies(slotLocal, windows)
}

//lint:ignore U1000 compatibility wrapper retained for transitional policy scheduler tests.
func candidatePriority(policy UpdatePolicy) [3]int {
	return defaultPolicyService().CandidatePriority(policy)
}

func comparePolicyCandidates(a, b scheduledPolicyCandidate) bool {
	return defaultPolicyService().ComparePolicyCandidates(
		policypkg.ScheduledCandidate{Policy: a.policy, Server: a.server, ScheduledForUTC: a.scheduledForUTC},
		policypkg.ScheduledCandidate{Policy: b.policy, Server: b.server, ScheduledForUTC: b.scheduledForUTC},
	)
}

//lint:ignore U1000 compatibility wrapper retained for transitional policy scheduler tests.
func createSkippedPolicyRun(policy UpdatePolicy, serverName, scheduledForUTC, reason, summary string) {
	defaultPolicyService().CreateSkippedRun(policy, serverName, scheduledForUTC, reason, summary)
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
	if !backupRestoreMu.TryRLock() {
		markScheduledPolicyRunMaintenanceSkipped(run, policy, server, "Maintenance mode active; scheduled run skipped")
		return
	}
	defer backupRestoreMu.RUnlock()
	if currentMaintenanceState().Active {
		markScheduledPolicyRunMaintenanceSkipped(run, policy, server, "Maintenance mode active; scheduled run skipped")
		return
	}

	switch policy.ExecutionMode {
	case updatePolicyExecutionScanOnly:
		runScheduledScanPolicy(run, policy, server)
	default:
		runScheduledUpdatePolicy(run, policy, server)
	}
}

func markScheduledPolicyRunMaintenanceSkipped(run UpdatePolicyRun, policy UpdatePolicy, server Server, summary string) {
	status := updatePolicyRunSkipped
	reason := updatePolicyRunReasonMaintenance
	finishedAt := jobTimestampNow()
	_ = updateUpdatePolicyRun(run.ID, updatePolicyRunUpdate{
		Status:     &status,
		Reason:     &reason,
		Summary:    &summary,
		FinishedAt: &finishedAt,
	})
	auditWithActor("system", "", "schedule.run.skipped", "server", server.Name, "skipped", summary, map[string]any{
		"policy_id":         policy.ID,
		"policy_name":       policy.Name,
		"scheduled_for_utc": run.ScheduledForUTC,
	})
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
	serverForRun, err := beginServerAction(server.Name, "updating")
	if err != nil {
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
		runScheduledScanJob(job.ID, run.ID, run.ScheduledForUTC, serverForRun, policy, retryPolicy)
	})
	watchUpdatePolicyRunForJob(run.ID, job.ID)
}

func runScheduledScanJob(jobID string, runID int64, scheduledForUTC string, server Server, policy UpdatePolicy, retryPolicy RetryPolicy) {
	defaultUpdateService().RunScheduledScanJob(ScheduledScanRunRequest{
		JobID:           jobID,
		RunID:           runID,
		ScheduledForUTC: scheduledForUTC,
		Server:          server,
		Policy:          policy,
		RetryPolicy:     retryPolicy,
	})
}

func (s *UpdateService) RunScheduledScanJob(req ScheduledScanRunRequest) {
	s.ensureDeps()
	jm := s.deps.CurrentJobManager()
	setFailure := func(summary string, err error, phase string, logs string) {
		if jm != nil && strings.TrimSpace(req.JobID) != "" {
			status := jobStatusFailed
			jobPhase := phase
			finishedAt := s.deps.JobTimestampNow()
			errorClass := "permanent"
			_ = jm.UpdateJobWithoutRuntimeSync(req.JobID, JobUpdate{
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
		finishedAt := s.deps.JobTimestampNow()
		_ = s.deps.UpdatePolicyRun(req.RunID, updatePolicyRunUpdate{
			Status:     &runStatus,
			Reason:     &reason,
			Summary:    &summary,
			FinishedAt: &finishedAt,
		})
		meta := map[string]any{
			"policy_id":      req.Policy.ID,
			"policy_name":    req.Policy.Name,
			"execution_mode": req.Policy.ExecutionMode,
			"package_scope":  req.Policy.PackageScope,
		}
		if err != nil {
			meta["error"] = err.Error()
		}
		s.deps.AuditWithActor("system", "", "schedule.run.failed", "server", req.Server.Name, "failure", summary, meta)
	}

	authMethods, err := s.deps.BuildAuthMethods(req.Server)
	if err != nil {
		setFailure("Scheduled scan auth setup failed", err, jobPhaseDial, "")
		return
	}
	hostKeyCallback, err := s.deps.HostKeyCallback()
	if err != nil {
		setFailure("Scheduled scan host key setup failed", err, jobPhaseDial, "")
		return
	}
	config := &ssh.ClientConfig{
		User:            req.Server.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}
	client, err := s.deps.DialSSHWithRetry(req.Server, config, req.RetryPolicy, "scheduled_scan.ssh_dial", nil)
	if err != nil {
		setFailure("Scheduled scan SSH connection failed", err, jobPhaseDial, "")
		return
	}
	defer func() { _ = client.Close() }()

	logs := "Starting scheduled package scan..."
	if jm != nil {
		phase := jobPhasePrechecks
		summary := "Running pre-checks"
		_ = jm.UpdateJobWithoutRuntimeSync(req.JobID, JobUpdate{
			Phase:    &phase,
			Summary:  &summary,
			LogsText: &logs,
		})
	}
	precheckSummary := s.deps.RunUpdatePrechecks(client)
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
		_ = jm.UpdateJobWithoutRuntimeSync(req.JobID, JobUpdate{
			Phase:    &phase,
			Summary:  &summary,
			LogsText: &logs,
		})
	}
	var stdout, stderr string
	err = s.deps.RunSSHOperationWithRetry(
		req.Server,
		config,
		&client,
		req.RetryPolicy,
		"scheduled_scan.apt_update",
		"\napt update attempt %d/%d failed: %v; retrying in %s",
		new(int),
		func() error {
			var runErr error
			stdout, stderr, runErr = s.deps.RunSSHCommandWithTimeout(client, aptUpdateCmd, nil, s.deps.LoadCommandTimeout())
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
	err = s.deps.RunSSHOperationWithRetry(
		req.Server,
		config,
		&client,
		req.RetryPolicy,
		"scheduled_scan.list_upgradable",
		"\nlist upgradable attempt %d/%d failed: %v; retrying in %s",
		new(int),
		func() error {
			var listErr error
			pendingUpdates, upgradable, listErr = s.deps.GetUpgradable(client, s.deps.LoadCommandTimeout())
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
		cves, lookupErr := s.deps.QueryPackageCVEs(client, pendingUpdates[i].Package)
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
		meta := buildScheduledJobMeta(req.Policy, req.ScheduledForUTC)
		meta.Discovery = &result
		metaJSON := marshalJobJSON(meta)
		finishedAt := s.deps.JobTimestampNow()
		_ = jm.UpdateJobWithoutRuntimeSync(req.JobID, JobUpdate{
			Status:     &status,
			Phase:      &phase,
			Summary:    &finalSummary,
			LogsText:   &logs,
			MetaJSON:   &metaJSON,
			FinishedAt: &finishedAt,
		})
	}
	runStatus := updatePolicyRunSucceeded
	finishedAt := s.deps.JobTimestampNow()
	_ = s.deps.UpdatePolicyRun(req.RunID, updatePolicyRunUpdate{
		Status:     &runStatus,
		Summary:    &finalSummary,
		ResultJSON: &resultJSON,
		FinishedAt: &finishedAt,
	})
	s.deps.AuditWithActor("system", "", "schedule.run.completed", "server", req.Server.Name, "success", finalSummary, map[string]any{
		"policy_id":              req.Policy.ID,
		"policy_name":            req.Policy.Name,
		"pending_package_count":  result.PendingPackageCount,
		"security_package_count": result.SecurityPackageCount,
	})
}

//lint:ignore U1000 compatibility wrapper retained for transitional missed-tick tests.
func rememberMissedUpdatePolicyTick(now time.Time) {
	defaultPolicyService().RememberMissedTick(now)
}

//lint:ignore U1000 compatibility wrapper retained for transitional missed-tick tests.
func pendingMissedUpdatePolicyTicks() []time.Time {
	return defaultPolicyService().PendingMissedTicks()
}

//lint:ignore U1000 compatibility wrapper retained for transitional missed-tick tests.
func forgetMissedUpdatePolicyTick(tick time.Time) {
	defaultPolicyService().ForgetMissedTick(tick)
}

func resetMissedUpdatePolicyTicksForTest() {
	defaultPolicyService().ResetMissedTicksForTest()
}

//lint:ignore U1000 compatibility wrapper retained for transitional policy scheduler tests.
func processDueUpdatePolicySlot(now time.Time, maintenanceActive bool) error {
	return defaultPolicyService().ProcessDueSlot(PolicyScheduleRequest{Now: now, MaintenanceActive: maintenanceActive})
}

func processDueUpdatePolicies(now time.Time) error {
	return defaultPolicyService().ProcessDue(now)
}

func startUpdatePolicyScheduler(ctx context.Context) {
	startPolicyScheduler(defaultPolicyService(), ctx, PolicySchedulerOptions{})
}

//lint:ignore U1000 compatibility handler retained for direct handler tests and route migration.
func handleUpdatePoliciesList(c *gin.Context) {
	handleUpdatePoliciesListWithDeps(c, NewDefaultAppDeps())
}

func handleUpdatePoliciesListWithDeps(c *gin.Context, deps AppDeps) {
	deps = deps.withDefaults()
	policyDeps := deps.PolicyService.EnsureDeps()
	policies, err := policyDeps.ListPolicies()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load update policies"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":             enrichPoliciesWithMatchesUsing(deps.PolicyService, policies),
		"timezone":          deps.AppTimezoneDisplayName(),
		"resolved_timezone": deps.AppTimezoneResolvedName(),
	})
}

//lint:ignore U1000 compatibility handler retained for direct handler tests and route migration.
func handleUpdatePolicyCreate(c *gin.Context) {
	handleUpdatePolicyCreateWithDeps(c, NewDefaultAppDeps())
}

func handleUpdatePolicyCreateWithDeps(c *gin.Context, deps AppDeps) {
	deps = deps.withDefaults()
	var policy UpdatePolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		audit(c, "update_policy.create", "update_policy", "-", "failure", "Invalid request payload", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	created, err := createUpdatePolicyWithService(deps.PolicyService, policy)
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

//lint:ignore U1000 compatibility handler retained for direct handler tests and route migration.
func handleUpdatePolicyUpdate(c *gin.Context) {
	handleUpdatePolicyUpdateWithDeps(c, NewDefaultAppDeps())
}

func handleUpdatePolicyUpdateWithDeps(c *gin.Context, deps AppDeps) {
	deps = deps.withDefaults()
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
	updated, err := updateUpdatePolicyWithService(deps.PolicyService, id, policy)
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

//lint:ignore U1000 compatibility handler retained for direct handler tests and route migration.
func handleUpdatePolicyRuns(c *gin.Context) {
	handleUpdatePolicyRunsWithDeps(c, NewDefaultAppDeps())
}

func handleUpdatePolicyRunsWithDeps(c *gin.Context, deps AppDeps) {
	deps = deps.withDefaults()
	rawLimit := strings.TrimSpace(c.DefaultQuery("limit", strconv.Itoa(defaultUpdatePolicyRunsLimit)))
	limit, err := strconv.Atoi(rawLimit)
	if err != nil || limit <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be a positive integer"})
		return
	}
	if limit > maxUpdatePolicyRunsLimit {
		limit = maxUpdatePolicyRunsLimit
	}
	runs, err := listUpdatePolicyRuns(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load policy runs"})
		return
	}
	loc, timezoneName := deps.CurrentAppTimezone()
	for i := range runs {
		runs[i].ScheduledForDisplay, _ = formatTimestampForAppDisplayWithTimezone(runs[i].ScheduledForUTC, loc, timezoneName)
	}
	c.JSON(http.StatusOK, gin.H{
		"items":             runs,
		"timezone":          deps.AppTimezoneDisplayName(),
		"resolved_timezone": deps.AppTimezoneResolvedName(),
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

//lint:ignore U1000 compatibility handler retained for direct handler tests and route migration.
func handleUpdatePolicySettingsStatus(c *gin.Context) {
	handleUpdatePolicySettingsStatusWithDeps(c, NewDefaultAppDeps())
}

func handleUpdatePolicySettingsStatusWithDeps(c *gin.Context, deps AppDeps) {
	deps = deps.withDefaults()
	windows, err := loadGlobalUpdatePolicyBlackouts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load scheduled update settings"})
		return
	}
	c.JSON(http.StatusOK, UpdatePolicySettingsResponse{
		Timezone:         deps.AppTimezoneDisplayName(),
		ResolvedTimezone: deps.AppTimezoneResolvedName(),
		GlobalBlackouts:  windows,
	})
}

//lint:ignore U1000 compatibility handler retained for direct handler tests and route migration.
func handleUpdatePolicySettingsUpdate(c *gin.Context) {
	handleUpdatePolicySettingsUpdateWithDeps(c, NewDefaultAppDeps())
}

func handleUpdatePolicySettingsUpdateWithDeps(c *gin.Context, deps AppDeps) {
	deps = deps.withDefaults()
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
		Timezone:         deps.AppTimezoneDisplayName(),
		ResolvedTimezone: deps.AppTimezoneResolvedName(),
		GlobalBlackouts:  normalizedBlackouts,
	})
}
