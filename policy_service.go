package main

import (
	"context"
	"log"
	"time"
)

type PolicyServiceDeps struct {
	ListPolicies             func() ([]UpdatePolicy, error)
	LoadOverrides            func() (map[int64]map[string]bool, error)
	LoadGlobalBlackouts      func() ([]UpdatePolicyBlackoutWindow, error)
	SnapshotServers          func() []Server
	CurrentStatusSnapshot    func(string) *ServerStatus
	CreateRun                func(UpdatePolicyRun) (UpdatePolicyRun, bool, error)
	ExecuteRun               func(UpdatePolicyRun, UpdatePolicy, Server)
	AuditWithActor           func(actor, clientIP, action, targetType, targetName, status, message string, meta map[string]any)
	CurrentLocation          func() *time.Location
	CurrentMaintenanceActive func() bool
	JobTimestampNow          func() string
	MarkInterruptedRuns      func() error
	TryBackupRestoreReadLock func() bool
	UnlockBackupRestoreRead  func()
	Now                      func() time.Time
	Logf                     func(string, ...any)
}

type PolicyScheduleRequest struct {
	Now               time.Time
	MaintenanceActive bool
}

type PolicyMatchContext struct {
	Overrides map[int64]map[string]bool
}

type PolicySchedulerOptions struct {
	TickInterval time.Duration
}

type PolicyService struct {
	deps PolicyServiceDeps
}

func NewPolicyService(deps PolicyServiceDeps) *PolicyService {
	return &PolicyService{deps: deps.withDefaults()}
}

func defaultPolicyService() *PolicyService {
	return NewPolicyService(PolicyServiceDeps{})
}

func (s *PolicyService) ensureDeps() PolicyServiceDeps {
	if s == nil {
		return PolicyServiceDeps{}.withDefaults()
	}
	return s.deps.withDefaults()
}

func (d PolicyServiceDeps) withDefaults() PolicyServiceDeps {
	if d.ListPolicies == nil {
		d.ListPolicies = listUpdatePolicies
	}
	if d.LoadOverrides == nil {
		d.LoadOverrides = loadAllUpdatePolicyOverrides
	}
	if d.LoadGlobalBlackouts == nil {
		d.LoadGlobalBlackouts = loadGlobalUpdatePolicyBlackouts
	}
	if d.SnapshotServers == nil {
		d.SnapshotServers = snapshotServers
	}
	if d.CurrentStatusSnapshot == nil {
		d.CurrentStatusSnapshot = currentStatusSnapshot
	}
	if d.CreateRun == nil {
		d.CreateRun = createUpdatePolicyRun
	}
	if d.ExecuteRun == nil {
		d.ExecuteRun = executeScheduledPolicyRun
	}
	if d.AuditWithActor == nil {
		d.AuditWithActor = auditWithActor
	}
	if d.CurrentLocation == nil {
		d.CurrentLocation = currentAppLocation
	}
	if d.CurrentMaintenanceActive == nil {
		d.CurrentMaintenanceActive = func() bool {
			return currentMaintenanceState().Active
		}
	}
	if d.JobTimestampNow == nil {
		d.JobTimestampNow = jobTimestampNow
	}
	if d.MarkInterruptedRuns == nil {
		d.MarkInterruptedRuns = markInterruptedUpdatePolicyRuns
	}
	switch {
	case d.TryBackupRestoreReadLock == nil && d.UnlockBackupRestoreRead == nil:
		d.TryBackupRestoreReadLock = backupRestoreMu.TryRLock
		d.UnlockBackupRestoreRead = backupRestoreMu.RUnlock
	case d.TryBackupRestoreReadLock != nil && d.UnlockBackupRestoreRead != nil:
	case d.TryBackupRestoreReadLock != nil:
		d.UnlockBackupRestoreRead = func() {}
	default:
		d.TryBackupRestoreReadLock = func() bool { return true }
		d.UnlockBackupRestoreRead = func() {}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logf == nil {
		d.Logf = log.Printf
	}
	return d
}

func (o PolicySchedulerOptions) withDefaults() PolicySchedulerOptions {
	if o.TickInterval <= 0 {
		o.TickInterval = updatePolicyTickInterval
	}
	return o
}

func (s *PolicyService) StartScheduler(ctx context.Context, options PolicySchedulerOptions) {
	deps := s.ensureDeps()
	options = options.withDefaults()
	updatePolicySchedulerOnce.Do(func() {
		if err := deps.MarkInterruptedRuns(); err != nil {
			deps.Logf("failed to mark interrupted policy runs: %v", err)
		}
		if err := s.ProcessDue(deps.Now()); err != nil {
			deps.Logf("scheduled policy tick failed: %v", err)
		}
		go func() {
			ticker := time.NewTicker(options.TickInterval)
			defer ticker.Stop()
			for {
				select {
				case tick := <-ticker.C:
					if err := s.ProcessDue(tick); err != nil {
						deps.Logf("scheduled policy tick failed: %v", err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	})
}
