package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	internalbackup "debian-updater/internal/backup"
	"debian-updater/internal/events"
	policypkg "debian-updater/internal/policies"
	serverpkg "debian-updater/internal/servers"
	updatespkg "debian-updater/internal/updates"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/crypto/ssh"
)

type AppDeps struct {
	DB     func() *sql.DB
	DBPath func() string

	AuditService           *AuditService
	AuthService            *AuthService
	BackupService          *BackupService
	BackupBarrier          *BackupBarrier
	ServerState            *serverpkg.State
	ServerInventoryService *ServerInventoryService
	PolicyService          *PolicyService
	PolicyRepository       policypkg.Repository
	UpdateService          *UpdateService
	ObservabilityService   *ObservabilityService
	MetricsTokenService    *MetricsTokenService

	JobManager           *JobManager
	CurrentJobManager    func() *JobManager
	NewJobManager        func(*sql.DB) *JobManager
	SetCurrentJobManager func(*JobManager)

	GetGlobalKey   func() string
	SetGlobalKey   func(string) error
	ClearGlobalKey func() error
	HasGlobalKey   func() (bool, error)

	SessionManager            *scs.SessionManager
	CurrentSessionManager     func() *scs.SessionManager
	NewSessionManager         func(*sql.DB) (*scs.SessionManager, error)
	SetSessionManager         func(*scs.SessionManager)
	LoginRateLimiter          *AuthRateLimiter
	PasswordChangeRateLimiter *AuthRateLimiter
	SetupRateLimiter          *AuthRateLimiter
	MetricsRateLimiter        *AuthRateLimiter

	TrustedProxies             func() []string
	InitializeMaintenanceState func() error
	CurrentMaintenanceActive   func() bool
	Now                        func() time.Time
	NotifyDashboardEvent       func(string)
	DashboardEventBroker       *events.Broker
	CurrentAppTimezone         func() (*time.Location, string)
	CurrentAppLocation         func() *time.Location
	AppTimezoneDisplayName     func() string
	AppTimezoneResolvedName    func() string
}

func NewDefaultAppDeps() AppDeps {
	return AppDeps{}.withDefaults()
}

func (deps AppDeps) withDefaults() AppDeps {
	if deps.DB == nil {
		deps.DB = getDB
	}
	if deps.DBPath == nil {
		deps.DBPath = dbPath
	}
	if deps.CurrentAppTimezone == nil {
		deps.CurrentAppTimezone = currentAppTimezone
	}
	if deps.CurrentAppLocation == nil {
		deps.CurrentAppLocation = currentAppLocation
	}
	if deps.AppTimezoneDisplayName == nil {
		deps.AppTimezoneDisplayName = currentAppTimezoneDisplayName
	}
	if deps.AppTimezoneResolvedName == nil {
		deps.AppTimezoneResolvedName = currentAppTimezoneResolvedName
	}
	if deps.DashboardEventBroker == nil {
		deps.DashboardEventBroker = events.NewBroker()
	}
	if deps.NotifyDashboardEvent == nil {
		broker := deps.DashboardEventBroker
		deps.NotifyDashboardEvent = func(reason string) {
			if broker != nil {
				broker.Publish(reason)
			}
		}
	}
	if deps.AuthService == nil {
		deps.AuthService = NewAuthService(deps.DB)
	}
	if deps.AuditService == nil {
		deps.AuditService = NewAuditService(deps.DB, deps.NotifyDashboardEvent, deps.CurrentAppTimezone)
	}
	if deps.BackupBarrier == nil {
		deps.BackupBarrier = backupRestoreMu
	}
	if deps.MetricsTokenService == nil {
		deps.MetricsTokenService = NewMetricsTokenService(MetricsTokenDeps{
			DB:     deps.DB,
			DBPath: deps.DBPath,
		})
	}
	if deps.ServerState == nil {
		deps.ServerState = newServerState()
	}
	if deps.ServerInventoryService == nil {
		deps.ServerInventoryService = newServerInventoryServiceWithStateDBPath(deps.ServerState, deps.DB, deps.DBPath)
	}
	if deps.NewJobManager == nil {
		notify := deps.NotifyDashboardEvent
		deps.NewJobManager = func(db *sql.DB) *JobManager {
			return newJobManagerWithRuntime(db, notify, deps.ServerState, deps.CurrentMaintenanceActive)
		}
	}
	if deps.CurrentJobManager == nil {
		var jobMu sync.RWMutex
		manager := deps.JobManager
		setManager := deps.SetCurrentJobManager
		deps.CurrentJobManager = func() *JobManager {
			jobMu.RLock()
			jm := manager
			jobMu.RUnlock()
			if jm != nil {
				return jm
			}
			return currentJobManager()
		}
		deps.SetCurrentJobManager = func(jm *JobManager) {
			jobMu.Lock()
			manager = jm
			jobMu.Unlock()
			if setManager != nil {
				setManager(jm)
				return
			}
			setCurrentJobManager(jm)
		}
	} else if deps.SetCurrentJobManager == nil {
		deps.SetCurrentJobManager = setCurrentJobManager
	}
	if deps.GetGlobalKey == nil || deps.SetGlobalKey == nil || deps.ClearGlobalKey == nil || deps.HasGlobalKey == nil {
		getKey, setKey, clearKey, hasKey := newAppGlobalKeyStore(deps.DB)
		if deps.GetGlobalKey == nil {
			deps.GetGlobalKey = getKey
		}
		if deps.SetGlobalKey == nil {
			deps.SetGlobalKey = setKey
		}
		if deps.ClearGlobalKey == nil {
			deps.ClearGlobalKey = clearKey
		}
		if deps.HasGlobalKey == nil {
			deps.HasGlobalKey = hasKey
		}
	}
	if deps.PolicyRepository == nil {
		deps.PolicyRepository = policypkg.NewSQLiteRepository(policypkg.SQLiteRepositoryDeps{
			DB:          deps.DB,
			NowString:   jobTimestampNow,
			MarshalJSON: marshalJobJSON,
		})
	}
	if deps.CurrentMaintenanceActive == nil {
		deps.CurrentMaintenanceActive = func() bool {
			return currentMaintenanceState().Active
		}
	}
	recordAudit := func(actor, clientIP, action, targetType, targetName, status, message string, meta map[string]any) {
		if err := deps.AuditService.Record(actor, clientIP, action, targetType, targetName, status, message, meta); err != nil {
			log.Printf("audit write failed: action=%s target=%s err=%v", action, targetName, err)
		}
	}
	factsRepo := updatespkg.SQLiteServerFactsRepository{DB: deps.DB}
	if deps.PolicyService == nil {
		deps.PolicyService = NewPolicyService(PolicyServiceDeps{
			ListPolicies:             deps.PolicyRepository.ListPolicies,
			LoadOverrides:            deps.PolicyRepository.LoadAllOverrides,
			LoadGlobalBlackouts:      deps.PolicyRepository.LoadGlobalBlackouts,
			AuditWithActor:           recordAudit,
			CurrentLocation:          deps.CurrentAppLocation,
			CurrentMaintenanceActive: deps.CurrentMaintenanceActive,
			TryBackupRestoreReadLock: deps.BackupBarrier.TryRLock,
			UnlockBackupRestoreRead:  deps.BackupBarrier.RUnlock,
			SnapshotServers: func() []Server {
				return deps.ServerState.CloneServers()
			},
			CurrentStatusSnapshot: func(name string) *ServerStatus {
				return deps.ServerState.CurrentStatusSnapshot(name)
			},
			CreateRun:           deps.PolicyRepository.CreateRun,
			MarkInterruptedRuns: deps.PolicyRepository.MarkInterruptedRuns,
			ExecuteRun: func(run UpdatePolicyRun, policy UpdatePolicy, server Server) {
				executeScheduledPolicyRunWithDeps(deps, run, policy, server)
			},
		})
	}
	if deps.UpdateService == nil {
		deps.UpdateService = NewUpdateService(UpdateServiceDeps{
			ServerState:       deps.ServerState,
			CurrentJobManager: deps.CurrentJobManager,
			StartJobRunner:    func(jobID string, run func()) { startJobRunnerWithManager(deps.CurrentJobManager, jobID, run) },
			BuildAuthMethods: func(server Server) ([]ssh.AuthMethod, error) {
				return serverpkg.BuildAuthMethods(server, deps.GetGlobalKey)
			},
			HostKeyCallback: func() (ssh.HostKeyCallback, error) {
				return serverpkg.HostKeyCallback(appKnownHostsDeps(deps.DBPath))
			},
			DialSSH: func(server Server, config *ssh.ClientConfig) (sshConnection, error) {
				return getDialSSHConnection()(server, config)
			},
			AuditWithActor:  recordAudit,
			SaveServerFacts: factsRepo.Save,
			UpdateScheduledDiscoveryMeta: func(jobID string, upgradable []string, pending []PendingUpdate) {
				updateScheduledJobDiscoveryMetaWithManager(deps.CurrentJobManager, jobID, upgradable, pending)
			},
			UpdatePolicyRun: deps.PolicyRepository.UpdateRun,
			LoadScheduledJobBehavior: func(jobID string) scheduledJobBehavior {
				return loadScheduledJobBehaviorWithManager(deps.CurrentJobManager, jobID)
			},
		})
	}
	if deps.ObservabilityService == nil {
		policyDeps := deps.PolicyService.EnsureDeps()
		deps.ObservabilityService = NewObservabilityService(ObservabilityServiceDeps{
			DB:              deps.DB,
			DBPath:          deps.DBPath,
			CurrentTimezone: deps.CurrentAppTimezone,
			CurrentLocation: deps.CurrentAppLocation,
			ServerSnapshot: func() ([]Server, map[string]*ServerStatus) {
				deps.ServerState.Lock()
				defer deps.ServerState.Unlock()
				return serverpkg.CloneServers(deps.ServerState.Servers()), serverpkg.CloneStatusMap(deps.ServerState.StatusMap())
			},
			LoadServerFacts:     factsRepo.LoadAll,
			ListPolicies:        policyDeps.ListPolicies,
			LoadOverrides:       policyDeps.LoadOverrides,
			LoadGlobalBlackouts: policyDeps.LoadGlobalBlackouts,
			ListPolicyRuns:      deps.PolicyRepository.ListRuns,
			PolicyMatchesServer: func(policy UpdatePolicy, server Server, overrides map[int64]map[string]bool) bool {
				return deps.PolicyService.PolicyMatchesServer(policy, server, PolicyMatchContext{Overrides: overrides})
			},
			PolicyDueAt:             deps.PolicyService.PolicyDueAt,
			BlackoutApplies:         deps.PolicyService.BlackoutApplies,
			ComparePolicyCandidates: deps.PolicyService.ComparePolicyCandidates,
		})
	}
	if deps.NewSessionManager == nil {
		deps.NewSessionManager = newSessionManager
	}
	if deps.CurrentSessionManager == nil {
		var sessionMu sync.RWMutex
		session := deps.SessionManager
		setSession := deps.SetSessionManager
		deps.CurrentSessionManager = func() *scs.SessionManager {
			sessionMu.RLock()
			sm := session
			sessionMu.RUnlock()
			if sm != nil {
				return sm
			}
			return currentSessionManager()
		}
		deps.SetSessionManager = func(sm *scs.SessionManager) {
			sessionMu.Lock()
			session = sm
			sessionMu.Unlock()
			if setSession != nil {
				setSession(sm)
				return
			}
			setGlobalSessionManager(sm)
		}
	} else if deps.SetSessionManager == nil {
		deps.SetSessionManager = setGlobalSessionManager
	}
	if deps.LoginRateLimiter == nil {
		deps.LoginRateLimiter = loginRateLimiter
	}
	if deps.PasswordChangeRateLimiter == nil {
		deps.PasswordChangeRateLimiter = passwordChangeRateLimiter
	}
	if deps.SetupRateLimiter == nil {
		deps.SetupRateLimiter = setupRateLimiter
	}
	if deps.MetricsRateLimiter == nil {
		deps.MetricsRateLimiter = metricsRateLimiter
	}
	if deps.TrustedProxies == nil {
		deps.TrustedProxies = trustedProxiesFromEnv
	}
	if deps.InitializeMaintenanceState == nil {
		deps.InitializeMaintenanceState = initializeMaintenanceState
	}
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Now().UTC() }
	}
	if deps.BackupService == nil {
		runtimeDeps := deps
		metricsTokenService := deps.MetricsTokenService
		deps.BackupService = NewBackupServiceWithDeps(internalbackup.ServiceDeps{
			DB:     deps.DB,
			DBPath: deps.DBPath,
			ResetRuntimeCaches: func() {
				resetRuntimeCaches()
				if metricsTokenService != nil {
					metricsTokenService.RestoreCache("", false, "")
				}
			},
			ReloadRuntimeState: func() error {
				return reloadAppRuntimeState(runtimeDeps)
			},
		})
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

func newAppGlobalKeyStore(dbProvider func() *sql.DB) (func() string, func(string) error, func() error, func() (bool, error)) {
	if dbProvider == nil {
		dbProvider = getDB
	}
	var keyMu sync.RWMutex
	cachedKey := ""
	getCached := func() string {
		keyMu.RLock()
		defer keyMu.RUnlock()
		return cachedKey
	}
	setCached := func(key string) {
		keyMu.Lock()
		cachedKey = key
		keyMu.Unlock()
		globalKeyMu.Lock()
		globalKey = key
		globalKeyMu.Unlock()
	}
	getKey := func() string {
		db := dbProvider()
		for attempt := 1; attempt <= 3; attempt++ {
			var enc string
			err := db.QueryRow("SELECT value FROM settings WHERE key = ?", globalKeySetting).Scan(&enc)
			if err == sql.ErrNoRows {
				setCached("")
				return ""
			}
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "database is locked") && attempt < 3 {
					time.Sleep(75 * time.Millisecond)
					continue
				}
				cached := getCached()
				log.Printf("Failed to load global SSH key: %v", err)
				if strings.TrimSpace(cached) != "" {
					log.Printf("Using cached global SSH key due to read failure")
				}
				return cached
			}
			key, decErr := decryptSecret(enc)
			if decErr != nil {
				cached := getCached()
				log.Printf("Failed to decrypt global SSH key: %v", decErr)
				if strings.TrimSpace(cached) != "" {
					log.Printf("Using cached global SSH key due to decrypt failure")
				}
				return cached
			}
			setCached(key)
			return key
		}
		return ""
	}
	setKey := func(key string) error {
		enc, err := encryptSecret(key)
		if err != nil {
			return err
		}
		if _, err := dbProvider().Exec(
			"INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			globalKeySetting, enc,
		); err != nil {
			return err
		}
		setCached(key)
		return nil
	}
	clearKey := func() error {
		if _, err := dbProvider().Exec("DELETE FROM settings WHERE key = ?", globalKeySetting); err != nil {
			return err
		}
		setCached("")
		return nil
	}
	hasKey := func() (bool, error) {
		var enc string
		err := dbProvider().QueryRow("SELECT value FROM settings WHERE key = ?", globalKeySetting).Scan(&enc)
		if err == sql.ErrNoRows {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(enc) == "" {
			return false, nil
		}
		return true, nil
	}
	return getKey, setKey, clearKey, hasKey
}

func reloadAppRuntimeState(deps AppDeps) error {
	if deps.DB == nil {
		deps.DB = getDB
	}
	_ = deps.DB()
	if deps.CurrentMaintenanceActive == nil {
		deps.CurrentMaintenanceActive = func() bool {
			return currentMaintenanceState().Active
		}
	}
	if deps.InitializeMaintenanceState == nil {
		deps.InitializeMaintenanceState = initializeMaintenanceState
	}
	if !deps.CurrentMaintenanceActive() {
		if err := deps.InitializeMaintenanceState(); err != nil {
			return err
		}
	}
	if deps.NewJobManager == nil {
		notify := deps.NotifyDashboardEvent
		deps.NewJobManager = func(db *sql.DB) *JobManager {
			return newJobManagerWithRuntime(db, notify, deps.ServerState, deps.CurrentMaintenanceActive)
		}
	}
	if deps.SetCurrentJobManager == nil {
		deps.SetCurrentJobManager = setCurrentJobManager
	}
	jm := deps.NewJobManager(deps.DB())
	if jm == nil {
		return fmt.Errorf("job manager unavailable")
	}
	if err := jm.MarkUnfinishedJobsInterrupted(); err != nil {
		return err
	}
	deps.SetCurrentJobManager(jm)
	if deps.ServerInventoryService != nil {
		deps.ServerInventoryService.Load()
		initializeServerStateStatuses(deps.ServerState)
	} else {
		loadServers()
	}
	if deps.GetGlobalKey != nil {
		_ = deps.GetGlobalKey()
	} else {
		_ = getGlobalKey()
	}
	_ = getMetricsBearerTokenHash()
	if deps.NewSessionManager == nil {
		deps.NewSessionManager = newSessionManager
	}
	if deps.SetSessionManager == nil {
		deps.SetSessionManager = setGlobalSessionManager
	}
	sm, err := deps.NewSessionManager(deps.DB())
	if err != nil {
		return err
	}
	deps.SetSessionManager(sm)
	return nil
}

func setGlobalSessionManager(sm *scs.SessionManager) {
	sessionManagerMu.Lock()
	sessionManager = sm
	sessionManagerMu.Unlock()
}
