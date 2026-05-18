package main

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/alexedwards/scs/v2"
)

type AppDeps struct {
	DB func() *sql.DB

	AuditService           *AuditService
	ServerInventoryService *ServerInventoryService
	PolicyService          *PolicyService
	UpdateService          *UpdateService

	JobManager           *JobManager
	CurrentJobManager    func() *JobManager
	NewJobManager        func(*sql.DB) *JobManager
	SetCurrentJobManager func(*JobManager)

	SessionManager    *scs.SessionManager
	NewSessionManager func(*sql.DB) (*scs.SessionManager, error)
	SetSessionManager func(*scs.SessionManager)

	TrustedProxies             func() []string
	InitializeMaintenanceState func() error
	NotifyDashboardEvent       func(string)
	CurrentAppTimezone         func() (*time.Location, string)
	CurrentAppLocation         func() *time.Location
}

func NewDefaultAppDeps() AppDeps {
	return AppDeps{}.withDefaults()
}

func (deps AppDeps) withDefaults() AppDeps {
	if deps.DB == nil {
		deps.DB = getDB
	}
	if deps.AuditService == nil {
		deps.AuditService = auditService
	}
	if deps.ServerInventoryService == nil {
		deps.ServerInventoryService = serverInventoryService
	}
	if deps.PolicyService == nil {
		deps.PolicyService = defaultPolicyService()
	}
	if deps.UpdateService == nil {
		deps.UpdateService = defaultUpdateService()
	}
	if deps.CurrentJobManager == nil {
		deps.CurrentJobManager = currentJobManager
	}
	if deps.NewJobManager == nil {
		deps.NewJobManager = newJobManager
	}
	if deps.SetCurrentJobManager == nil {
		deps.SetCurrentJobManager = setCurrentJobManager
	}
	if deps.NewSessionManager == nil {
		deps.NewSessionManager = newSessionManager
	}
	if deps.SetSessionManager == nil {
		deps.SetSessionManager = setGlobalSessionManager
	}
	if deps.TrustedProxies == nil {
		deps.TrustedProxies = trustedProxiesFromEnv
	}
	if deps.InitializeMaintenanceState == nil {
		deps.InitializeMaintenanceState = initializeMaintenanceState
	}
	if deps.NotifyDashboardEvent == nil {
		deps.NotifyDashboardEvent = notifyDashboardEvent
	}
	if deps.CurrentAppTimezone == nil {
		deps.CurrentAppTimezone = currentAppTimezone
	}
	if deps.CurrentAppLocation == nil {
		deps.CurrentAppLocation = currentAppLocation
	}
	return deps
}

func (deps AppDeps) initializeJobManager() error {
	deps = deps.withDefaults()
	jm := deps.JobManager
	if jm == nil {
		jm = deps.NewJobManager(deps.DB())
	}
	if jm == nil {
		return fmt.Errorf("job manager unavailable")
	}
	if err := jm.MarkUnfinishedJobsInterrupted(); err != nil {
		return err
	}
	deps.SetCurrentJobManager(jm)
	return nil
}

func (deps AppDeps) initializeSessionManager() error {
	deps = deps.withDefaults()
	sm := deps.SessionManager
	if sm == nil {
		var err error
		sm, err = deps.NewSessionManager(deps.DB())
		if err != nil {
			return err
		}
	}
	deps.SetSessionManager(sm)
	return nil
}

func setGlobalSessionManager(sm *scs.SessionManager) {
	sessionManagerMu.Lock()
	sessionManager = sm
	sessionManagerMu.Unlock()
}
