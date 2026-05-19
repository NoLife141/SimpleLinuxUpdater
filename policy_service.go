package main

import (
	"context"
	"log"
	"sync"
	"time"

	policypkg "debian-updater/internal/policies"
)

type PolicyServiceDeps = policypkg.ServiceDeps
type PolicyScheduleRequest = policypkg.ScheduleRequest
type PolicyMatchContext = policypkg.MatchContext
type PolicySchedulerOptions = policypkg.SchedulerOptions
type PolicyService = policypkg.Service

var (
	defaultPolicyServiceOnce sync.Once
	defaultPolicyServiceInst *PolicyService
)

func NewPolicyService(deps PolicyServiceDeps) *PolicyService {
	return policypkg.NewService(policyServiceDepsWithDefaults(deps))
}

func defaultPolicyService() *PolicyService {
	defaultPolicyServiceOnce.Do(func() {
		defaultPolicyServiceInst = NewPolicyService(PolicyServiceDeps{})
	})
	return defaultPolicyServiceInst
}

func policyServiceDepsWithDefaults(deps PolicyServiceDeps) PolicyServiceDeps {
	if deps.ListPolicies == nil {
		deps.ListPolicies = listUpdatePolicies
	}
	if deps.LoadOverrides == nil {
		deps.LoadOverrides = loadAllUpdatePolicyOverrides
	}
	if deps.LoadGlobalBlackouts == nil {
		deps.LoadGlobalBlackouts = loadGlobalUpdatePolicyBlackouts
	}
	if deps.SnapshotServers == nil {
		deps.SnapshotServers = snapshotServers
	}
	if deps.CurrentStatusSnapshot == nil {
		deps.CurrentStatusSnapshot = currentStatusSnapshot
	}
	if deps.CreateRun == nil {
		deps.CreateRun = createUpdatePolicyRun
	}
	if deps.ExecuteRun == nil {
		deps.ExecuteRun = executeScheduledPolicyRun
	}
	if deps.AuditWithActor == nil {
		deps.AuditWithActor = auditWithActor
	}
	if deps.CurrentLocation == nil {
		deps.CurrentLocation = currentAppLocation
	}
	if deps.CurrentMaintenanceActive == nil {
		deps.CurrentMaintenanceActive = func() bool {
			return currentMaintenanceState().Active
		}
	}
	if deps.JobTimestampNow == nil {
		deps.JobTimestampNow = jobTimestampNow
	}
	if deps.MarkInterruptedRuns == nil {
		deps.MarkInterruptedRuns = markInterruptedUpdatePolicyRuns
	}
	switch {
	case deps.TryBackupRestoreReadLock == nil && deps.UnlockBackupRestoreRead == nil:
		deps.TryBackupRestoreReadLock = backupRestoreMu.TryRLock
		deps.UnlockBackupRestoreRead = backupRestoreMu.RUnlock
	case deps.TryBackupRestoreReadLock != nil && deps.UnlockBackupRestoreRead != nil:
	case deps.TryBackupRestoreReadLock != nil:
		deps.UnlockBackupRestoreRead = func() {}
	default:
		deps.TryBackupRestoreReadLock = func() bool { return true }
		deps.UnlockBackupRestoreRead = func() {}
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Logf == nil {
		deps.Logf = log.Printf
	}
	if deps.StatusInProgress == nil {
		deps.StatusInProgress = statusInProgress
	}
	if deps.TimestampLayout == "" {
		deps.TimestampLayout = jobTimestampLayout
	}
	return deps
}

func startPolicyScheduler(service *PolicyService, ctx context.Context, options PolicySchedulerOptions) {
	if service == nil {
		service = defaultPolicyService()
	}
	service.StartScheduler(ctx, options)
}
