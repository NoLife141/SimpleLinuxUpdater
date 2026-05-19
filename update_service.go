package main

import (
	"log"
	"strings"
	"time"

	updatespkg "debian-updater/internal/updates"

	"golang.org/x/crypto/ssh"
)

type UpdateServiceDeps = updatespkg.ServiceDeps
type UpdateService = updatespkg.Service
type UpdateRunRequest = updatespkg.UpdateRunRequest
type AutoremoveRunRequest = updatespkg.AutoremoveRunRequest
type SudoersRunRequest = updatespkg.SudoersRunRequest
type ScheduledScanRunRequest = updatespkg.ScheduledScanRunRequest
type scheduledJobBehavior = updatespkg.ScheduledJobBehavior
type scheduledJobDiscovery = updatespkg.ScheduledJobDiscovery
type scheduledJobMeta = updatespkg.ScheduledJobMeta

func NewUpdateService(deps UpdateServiceDeps) *UpdateService {
	return updatespkg.NewService(updateServiceDepsWithDefaults(deps))
}

func defaultUpdateService() *UpdateService {
	return NewUpdateService(UpdateServiceDeps{})
}

func defaultServerFactsRepository() updatespkg.SQLiteServerFactsRepository {
	return updatespkg.SQLiteServerFactsRepository{DB: getDB}
}

func updateServiceDepsWithDefaults(d UpdateServiceDeps) UpdateServiceDeps {
	if d.ServerState == nil {
		d.ServerState = serverState
	}
	if d.BuildAuthMethods == nil {
		d.BuildAuthMethods = buildAuthMethods
	}
	if d.HostKeyCallback == nil {
		d.HostKeyCallback = getHostKeyCallback
	}
	if d.DialSSH == nil {
		d.DialSSH = getDialSSHConnection()
	}
	if d.DialSSHWithRetry == nil {
		d.DialSSHWithRetry = dialSSHWithRetry
	}
	if d.RunSSHOperationWithRetry == nil {
		d.RunSSHOperationWithRetry = runSSHOperationWithRetry
	}
	if d.RunSSHCommandWithTimeout == nil {
		d.RunSSHCommandWithTimeout = runSSHCommandWithTimeout
	}
	if d.CurrentJobManager == nil {
		d.CurrentJobManager = currentJobManager
	}
	if d.StartJobRunner == nil {
		d.StartJobRunner = startJobRunner
	}
	if d.AuditWithActor == nil {
		d.AuditWithActor = auditWithActor
	}
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.JobTimestampNow == nil {
		d.JobTimestampNow = jobTimestampNow
	}
	if d.LoadCommandTimeout == nil {
		d.LoadCommandTimeout = loadSSHCommandTimeoutFromEnv
	}
	if d.LoadPostUpdateCheckConfig == nil {
		d.LoadPostUpdateCheckConfig = loadPostUpdateCheckConfigFromEnv
	}
	if d.LoadScheduledJobBehavior == nil {
		d.LoadScheduledJobBehavior = loadScheduledJobBehavior
	}
	if d.RunUpdatePrechecks == nil {
		d.RunUpdatePrechecks = runUpdatePrechecks
	}
	if d.RunPostUpdateHealthChecks == nil {
		d.RunPostUpdateHealthChecks = runPostUpdateHealthChecks
	}
	if d.ListFailedSystemdUnits == nil {
		d.ListFailedSystemdUnits = listFailedSystemdUnits
	}
	if d.CollectServerFacts == nil {
		d.CollectServerFacts = collectServerFactsWithConnection
	}
	if d.SaveServerFacts == nil {
		d.SaveServerFacts = saveServerFacts
	}
	if d.GetUpgradable == nil {
		d.GetUpgradable = getUpgradable
	}
	if d.QueryPackageCVEs == nil {
		d.QueryPackageCVEs = queryPackageCVEs
	}
	if d.UpdateScheduledDiscoveryMeta == nil {
		d.UpdateScheduledDiscoveryMeta = updateScheduledJobDiscoveryMeta
	}
	if d.UpdatePolicyRun == nil {
		d.UpdatePolicyRun = updateUpdatePolicyRun
	}
	if d.IsPostcheckFailureBlocking == nil {
		d.IsPostcheckFailureBlocking = isPostcheckFailureBlocking
	}
	if d.SummarizeUnitNames == nil {
		d.SummarizeUnitNames = summarizeUnitNames
	}
	if d.Logf == nil {
		d.Logf = log.Printf
	}
	if d.SSHConnectTimeout <= 0 {
		d.SSHConnectTimeout = sshConnectTimeout
	}
	return d
}

func updateServiceEnsureDeps(service *UpdateService) UpdateServiceDeps {
	if service == nil {
		return updateServiceDepsWithDefaults(UpdateServiceDeps{})
	}
	return updateServiceDepsWithDefaults(service.EnsureDeps())
}

// withActorRunner is a temporary compatibility test seam. Runtime runner
// ownership lives in internal/updates; these methods preserve a few legacy
// main-package tests until the final wrapper cleanup phase.
type withActorRunner struct {
	service         *UpdateService
	server          Server
	policy          RetryPolicy
	jobID           string
	config          *ssh.ClientConfig
	client          sshConnection
	sshDialAttempts int
	lastErrClass    string
}

func (r *withActorRunner) deps() UpdateServiceDeps {
	if r != nil && r.service != nil {
		return updateServiceEnsureDeps(r.service)
	}
	return updateServiceDepsWithDefaults(UpdateServiceDeps{})
}

func (r *withActorRunner) setErrorLogs(logs string) {
	mu.Lock()
	if status := statusMap[r.server.Name]; status != nil {
		status.Status = "error"
		status.Logs = logs
	}
	mu.Unlock()
}

func (r *withActorRunner) markErrorClass(err error) {
	if isRetryableError(err) {
		r.lastErrClass = "transient"
		return
	}
	r.lastErrClass = "permanent"
}

func (r *withActorRunner) setupSSH(dialOpName string) bool {
	deps := r.deps()
	authMethods, err := deps.BuildAuthMethods(r.server)
	if err != nil {
		r.lastErrClass = "permanent"
		r.setErrorLogs("Auth setup failed: " + err.Error())
		return false
	}
	hostKeyCallback, err := deps.HostKeyCallback()
	if err != nil {
		r.lastErrClass = "permanent"
		r.setErrorLogs("Host key verification setup failed: " + err.Error())
		return false
	}
	r.config = &ssh.ClientConfig{
		User:            r.server.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}
	client, err := deps.DialSSHWithRetry(r.server, r.config, r.policy, dialOpName, &r.sshDialAttempts)
	if err != nil {
		r.markErrorClass(err)
		r.setErrorLogs("SSH connection failed: " + err.Error())
		return false
	}
	r.client = client
	return true
}

func (r *withActorRunner) currentJobManager() *JobManager {
	return r.deps().CurrentJobManager()
}

func (r *withActorRunner) syncJobFromStatus(snapshot *ServerStatus) {
	if snapshot == nil {
		return
	}
	jm := r.currentJobManager()
	if jm == nil || strings.TrimSpace(r.jobID) == "" {
		return
	}
	update := JobUpdate{LogsText: &snapshot.Logs}
	switch snapshot.Status {
	case "pending_approval":
		status := jobStatusWaitingApproval
		phase := jobPhaseApprovalWait
		summary := "Waiting for approval"
		update.Status = &status
		update.Phase = &phase
		update.Summary = &summary
	case "done":
		status := jobStatusSucceeded
		phase := jobPhaseComplete
		summary := "Completed successfully"
		finishedAt := jobTimestampNow()
		update.Status = &status
		update.Phase = &phase
		update.Summary = &summary
		update.FinishedAt = &finishedAt
	case "error":
		status := jobStatusFailed
		phase := jobPhaseComplete
		summary := "Completed with errors"
		finishedAt := jobTimestampNow()
		errorClass := strings.TrimSpace(r.lastErrClass)
		update.Status = &status
		update.Phase = &phase
		update.Summary = &summary
		update.FinishedAt = &finishedAt
		if errorClass != "" {
			update.ErrorClass = &errorClass
		}
	case "cancelled":
		status := jobStatusCancelled
		phase := jobPhaseComplete
		summary := "Cancelled"
		finishedAt := jobTimestampNow()
		update.Status = &status
		update.Phase = &phase
		update.Summary = &summary
		update.FinishedAt = &finishedAt
	case "approved":
		status := jobStatusRunning
		phase := jobPhaseAptUpgrade
		summary := "Approval received"
		update.Status = &status
		update.Phase = &phase
		update.Summary = &summary
	default:
		status := jobStatusRunning
		update.Status = &status
	}
	if _, err := jm.UpdateActiveJob(r.jobID, update); err != nil {
		log.Printf("failed to sync job %q from status %q: %v", r.jobID, snapshot.Status, err)
	}
}
