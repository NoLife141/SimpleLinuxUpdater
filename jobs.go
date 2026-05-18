package main

import (
	"database/sql"
	"log"
	"strings"
	"sync"
	"time"

	internaljobs "debian-updater/internal/jobs"
)

const (
	jobKindUpdate         = internaljobs.KindUpdate
	jobKindAutoremove     = internaljobs.KindAutoremove
	jobKindSudoersEnable  = internaljobs.KindSudoersEnable
	jobKindSudoersDisable = internaljobs.KindSudoersDisable
	jobKindCVEEnrichment  = internaljobs.KindCVEEnrichment
	jobKindBackupExport   = internaljobs.KindBackupExport
	jobKindBackupRestore  = internaljobs.KindBackupRestore
	jobKindScheduledScan  = internaljobs.KindScheduledScan

	jobStatusQueued          = internaljobs.StatusQueued
	jobStatusRunning         = internaljobs.StatusRunning
	jobStatusWaitingApproval = internaljobs.StatusWaitingApproval
	jobStatusSucceeded       = internaljobs.StatusSucceeded
	jobStatusFailed          = internaljobs.StatusFailed
	jobStatusCancelled       = internaljobs.StatusCancelled
	jobStatusInterrupted     = internaljobs.StatusInterrupted

	jobPhaseDial         = internaljobs.PhaseDial
	jobPhasePrechecks    = internaljobs.PhasePrechecks
	jobPhaseAptUpdate    = internaljobs.PhaseAptUpdate
	jobPhaseApprovalWait = internaljobs.PhaseApprovalWait
	jobPhaseAptUpgrade   = internaljobs.PhaseAptUpgrade
	jobPhasePostchecks   = internaljobs.PhasePostchecks
	jobPhaseAutoremove   = internaljobs.PhaseAutoremove
	jobPhaseApply        = internaljobs.PhaseApply
	jobPhaseSnapshot     = internaljobs.PhaseSnapshot
	jobPhaseEncrypt      = internaljobs.PhaseEncrypt
	jobPhaseDecrypt      = internaljobs.PhaseDecrypt
	jobPhaseLookup       = internaljobs.PhaseLookup
	jobPhaseComplete     = internaljobs.PhaseComplete

	jobTimestampLayout = internaljobs.TimestampLayout
)

type JobRecord = internaljobs.Record
type JobUpdate = internaljobs.Update
type JobCreateParams = internaljobs.CreateParams
type JobManager = internaljobs.Manager

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
	return internaljobs.NewManager(internaljobs.NewSQLiteRepository(db), internaljobs.ManagerOptions{
		MaintenanceActive: func() bool {
			return currentMaintenanceState().Active
		},
		MaintenanceError: errMaintenanceModeActive,
		Notify:           notifyDashboardEvent,
		SyncRuntime:      syncStatusMapFromJobRecord,
		SyncInterruptedServer: func(serverNames []string) {
			markInterruptedServersIdle(serverNames)
		},
	})
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
	return internaljobs.EnsureSchema(db)
}

func marshalJobJSON(v any) string {
	return internaljobs.MarshalJSON(v)
}

func formatJobTimestamp(t time.Time) string {
	return internaljobs.FormatTimestamp(t)
}

func jobTimestampNow() string {
	return formatJobTimestamp(time.Now())
}

func runtimeStatusFromJob(record JobRecord) string {
	switch record.Kind {
	case jobKindUpdate, jobKindAutoremove, jobKindSudoersEnable, jobKindSudoersDisable:
	default:
		return ""
	}

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

func syncStatusMapFromJobRecord(record JobRecord) {
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

func markInterruptedServersIdle(serverNames []string) {
	mu.Lock()
	defer mu.Unlock()
	for _, serverName := range serverNames {
		status := statusMap[serverName]
		if status == nil {
			continue
		}
		status.Status = "idle"
		status.ApprovalScope = ""
		status.Upgradable = nil
		status.PendingUpdates = nil
	}
}

func startJobRunner(jobID string, run func()) {
	startJobRunnerWithManager(currentJobManager, jobID, run)
}

func startJobRunnerWithManager(current func() *JobManager, jobID string, run func()) {
	if current == nil {
		current = currentJobManager
	}
	startTrackedActionRunner(func() {
		jm := current()
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
				if jm := current(); jm != nil && strings.TrimSpace(jobID) != "" {
					status := jobStatusFailed
					phase := jobPhaseComplete
					summary := "Runner panicked"
					errorClass := "panic"
					finishedAt := jobTimestampNow()
					_ = jm.UpdateJob(jobID, JobUpdate{
						Status:     &status,
						Phase:      &phase,
						Summary:    &summary,
						ErrorClass: &errorClass,
						FinishedAt: &finishedAt,
					})
				}
			}
		}()
		run()
	})
}
