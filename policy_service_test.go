package main

import (
	"errors"
	"testing"
	"time"
)

func testPolicyServiceDeps() PolicyServiceDeps {
	return PolicyServiceDeps{
		ListPolicies: func() ([]UpdatePolicy, error) {
			return nil, nil
		},
		LoadOverrides: func() (map[int64]map[string]bool, error) {
			return map[int64]map[string]bool{}, nil
		},
		LoadGlobalBlackouts: func() ([]UpdatePolicyBlackoutWindow, error) {
			return nil, nil
		},
		SnapshotServers: func() []Server {
			return nil
		},
		CurrentStatusSnapshot: func(string) *ServerStatus {
			return nil
		},
		CreateRun: func(run UpdatePolicyRun) (UpdatePolicyRun, bool, error) {
			return run, true, nil
		},
		ExecuteRun:     func(UpdatePolicyRun, UpdatePolicy, Server) {},
		AuditWithActor: func(string, string, string, string, string, string, string, map[string]any) {},
		CurrentLocation: func() *time.Location {
			return time.UTC
		},
		CurrentMaintenanceActive: func() bool {
			return false
		},
		JobTimestampNow: func() string {
			return "2026-01-02T03:04:05Z"
		},
		MarkInterruptedRuns: func() error {
			return nil
		},
		TryBackupRestoreReadLock: func() bool {
			return true
		},
		UnlockBackupRestoreRead: func() {},
		Now: func() time.Time {
			return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		},
		Logf: func(string, ...any) {},
	}
}

func TestPolicyServiceNormalizePolicyRequiresTarget(t *testing.T) {
	policy := UpdatePolicy{
		Name:          "Nightly",
		Enabled:       true,
		PackageScope:  updatePolicyPackageScopeSecurity,
		ExecutionMode: updatePolicyExecutionScanOnly,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     "03:00",
	}

	err := NewPolicyService(testPolicyServiceDeps()).NormalizePolicy(&policy)
	if err == nil {
		t.Fatalf("NormalizePolicy() error = nil, want no-target validation error")
	}
	if !errors.Is(wrapUpdatePolicyValidationError(err), errUpdatePolicyValidation) {
		t.Fatalf("wrapped validation error is not errUpdatePolicyValidation: %v", err)
	}
}

func TestPolicyServiceMatchesServersWithTargetsAndOverrides(t *testing.T) {
	service := NewPolicyService(testPolicyServiceDeps())
	server := Server{Name: "srv-a", Tags: []string{"prod", "db"}}

	tests := []struct {
		name      string
		policy    UpdatePolicy
		overrides map[int64]map[string]bool
		want      bool
	}{
		{
			name:   "explicit server",
			policy: UpdatePolicy{ID: 1, Enabled: true, TargetServers: []string{"SRV-A"}},
			want:   true,
		},
		{
			name:   "legacy target tag",
			policy: UpdatePolicy{ID: 2, Enabled: true, TargetTag: "PROD"},
			want:   true,
		},
		{
			name:   "include tag",
			policy: UpdatePolicy{ID: 3, Enabled: true, IncludeTags: []string{"db"}},
			want:   true,
		},
		{
			name:   "exclude wins",
			policy: UpdatePolicy{ID: 4, Enabled: true, IncludeTags: []string{"prod"}, ExcludeTags: []string{"DB"}},
			want:   false,
		},
		{
			name:      "override disables",
			policy:    UpdatePolicy{ID: 5, Enabled: true, TargetServers: []string{"srv-a"}},
			overrides: map[int64]map[string]bool{5: {"srv-a": true}},
			want:      false,
		},
		{
			name:   "disabled policy",
			policy: UpdatePolicy{ID: 6, Enabled: false, TargetServers: []string{"srv-a"}},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.overrides == nil {
				tt.overrides = map[int64]map[string]bool{}
			}
			got := service.PolicyMatchesServer(tt.policy, server, PolicyMatchContext{Overrides: tt.overrides})
			if got != tt.want {
				t.Fatalf("PolicyMatchesServer() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestPolicyServiceDueAndBlackoutWindowsUseLocalTime(t *testing.T) {
	service := NewPolicyService(testPolicyServiceDeps())
	loc := time.FixedZone("App", -5*60*60)
	slot := time.Date(2026, 1, 5, 23, 30, 0, 0, loc) // Monday

	if !service.PolicyDueAt(UpdatePolicy{
		Enabled:     true,
		CadenceKind: updatePolicyCadenceWeekly,
		TimeLocal:   "23:30",
		Weekdays:    []string{"mon"},
	}, slot) {
		t.Fatalf("PolicyDueAt() = false, want weekly local match")
	}

	overnight := []UpdatePolicyBlackoutWindow{{
		Weekdays:  []string{"mon"},
		StartTime: "22:00",
		EndTime:   "02:00",
	}}
	if !service.BlackoutApplies(slot, overnight) {
		t.Fatalf("BlackoutApplies(Monday 23:30) = false, want true")
	}
	tuesdayEarly := time.Date(2026, 1, 6, 1, 30, 0, 0, loc)
	if !service.BlackoutApplies(tuesdayEarly, overnight) {
		t.Fatalf("BlackoutApplies(Tuesday 01:30) = false, want overnight carryover")
	}
}

func TestPolicyServiceProcessDueQueuesWinnerAndSkipsSupersededBusyMissingAndBlackout(t *testing.T) {
	slot := time.Date(2026, 1, 5, 3, 0, 0, 0, time.UTC)
	policies := []UpdatePolicy{
		{
			ID:            1,
			Name:          "winner",
			Enabled:       true,
			TargetServers: []string{"srv-win"},
			PackageScope:  updatePolicyPackageScopeFull,
			ExecutionMode: updatePolicyExecutionApprovalRequired,
			CadenceKind:   updatePolicyCadenceDaily,
			TimeLocal:     "03:00",
			CreatedAt:     "2026-01-01T00:00:00Z",
		},
		{
			ID:            2,
			Name:          "superseded",
			Enabled:       true,
			TargetServers: []string{"srv-win"},
			PackageScope:  updatePolicyPackageScopeSecurity,
			ExecutionMode: updatePolicyExecutionScanOnly,
			CadenceKind:   updatePolicyCadenceDaily,
			TimeLocal:     "03:00",
			CreatedAt:     "2026-01-01T00:00:00Z",
		},
		{
			ID:            3,
			Name:          "busy",
			Enabled:       true,
			TargetServers: []string{"srv-busy"},
			PackageScope:  updatePolicyPackageScopeSecurity,
			ExecutionMode: updatePolicyExecutionScanOnly,
			CadenceKind:   updatePolicyCadenceDaily,
			TimeLocal:     "03:00",
		},
		{
			ID:            4,
			Name:          "missing",
			Enabled:       true,
			TargetServers: []string{"srv-missing"},
			PackageScope:  updatePolicyPackageScopeSecurity,
			ExecutionMode: updatePolicyExecutionScanOnly,
			CadenceKind:   updatePolicyCadenceDaily,
			TimeLocal:     "03:00",
		},
		{
			ID:            5,
			Name:          "blackout",
			Enabled:       true,
			TargetServers: []string{"srv-blackout"},
			PackageScope:  updatePolicyPackageScopeSecurity,
			ExecutionMode: updatePolicyExecutionScanOnly,
			CadenceKind:   updatePolicyCadenceDaily,
			TimeLocal:     "03:00",
			PolicyBlackouts: []UpdatePolicyBlackoutWindow{{
				Weekdays:  []string{"mon"},
				StartTime: "02:00",
				EndTime:   "04:00",
			}},
		},
		{
			ID:            6,
			Name:          "disabled",
			Enabled:       false,
			TargetServers: []string{"srv-disabled"},
			PackageScope:  updatePolicyPackageScopeSecurity,
			ExecutionMode: updatePolicyExecutionScanOnly,
			CadenceKind:   updatePolicyCadenceDaily,
			TimeLocal:     "03:00",
		},
	}
	servers := []Server{
		{Name: "srv-win"},
		{Name: "srv-busy"},
		{Name: "srv-missing"},
		{Name: "srv-blackout"},
		{Name: "srv-disabled"},
	}
	statusByServer := map[string]*ServerStatus{
		"srv-win":      {Name: "srv-win", Status: "idle"},
		"srv-busy":     {Name: "srv-busy", Status: "updating"},
		"srv-blackout": {Name: "srv-blackout", Status: "idle"},
		"srv-disabled": {Name: "srv-disabled", Status: "idle"},
	}

	var created []UpdatePolicyRun
	var executed []UpdatePolicyRun
	deps := testPolicyServiceDeps()
	deps.ListPolicies = func() ([]UpdatePolicy, error) {
		return append([]UpdatePolicy(nil), policies...), nil
	}
	deps.SnapshotServers = func() []Server {
		return append([]Server(nil), servers...)
	}
	deps.CurrentStatusSnapshot = func(name string) *ServerStatus {
		return statusByServer[name]
	}
	deps.CreateRun = func(run UpdatePolicyRun) (UpdatePolicyRun, bool, error) {
		run.ID = int64(len(created) + 1)
		created = append(created, run)
		return run, true, nil
	}
	deps.ExecuteRun = func(run UpdatePolicyRun, policy UpdatePolicy, server Server) {
		executed = append(executed, run)
	}

	if err := NewPolicyService(deps).ProcessDueSlot(PolicyScheduleRequest{Now: slot}); err != nil {
		t.Fatalf("ProcessDueSlot() unexpected error: %v", err)
	}

	if len(executed) != 1 || executed[0].PolicyID != 1 || executed[0].ServerName != "srv-win" {
		t.Fatalf("executed = %+v, want only winner on srv-win", executed)
	}
	reasons := map[string]string{}
	for _, run := range created {
		reasons[run.ServerName+":"+run.PolicyName] = run.Reason
	}
	wantReasons := map[string]string{
		"srv-win:superseded":    updatePolicyRunReasonSuperseded,
		"srv-busy:busy":         updatePolicyRunReasonBusy,
		"srv-missing:missing":   updatePolicyRunReasonMissing,
		"srv-blackout:blackout": updatePolicyRunReasonBlackout,
	}
	for key, want := range wantReasons {
		if reasons[key] != want {
			t.Fatalf("reason[%s] = %q, want %q; all runs=%+v", key, reasons[key], want, created)
		}
	}
	if _, exists := reasons["srv-disabled:disabled"]; exists {
		t.Fatalf("disabled policy created a run: %+v", created)
	}
}

func TestPolicyServiceProcessDueRemembersAndReplaysMissedTicks(t *testing.T) {
	service := NewPolicyService(testPolicyServiceDeps())
	service.ResetMissedTicksForTest()
	t.Cleanup(service.ResetMissedTicksForTest)

	slot := time.Date(2026, 1, 5, 3, 0, 0, 0, time.UTC)
	var lockAvailable bool
	var created []UpdatePolicyRun
	deps := testPolicyServiceDeps()
	deps.TryBackupRestoreReadLock = func() bool {
		return lockAvailable
	}
	deps.UnlockBackupRestoreRead = func() {}
	deps.ListPolicies = func() ([]UpdatePolicy, error) {
		return []UpdatePolicy{{
			ID:            7,
			Name:          "maintenance replay",
			Enabled:       true,
			TargetServers: []string{"srv"},
			PackageScope:  updatePolicyPackageScopeSecurity,
			ExecutionMode: updatePolicyExecutionScanOnly,
			CadenceKind:   updatePolicyCadenceDaily,
			TimeLocal:     "03:00",
		}}, nil
	}
	deps.SnapshotServers = func() []Server {
		return []Server{{Name: "srv"}}
	}
	deps.CurrentStatusSnapshot = func(string) *ServerStatus {
		return &ServerStatus{Name: "srv", Status: "idle"}
	}
	deps.CreateRun = func(run UpdatePolicyRun) (UpdatePolicyRun, bool, error) {
		created = append(created, run)
		return run, true, nil
	}

	service = NewPolicyService(deps)
	if err := service.ProcessDue(slot); err != nil {
		t.Fatalf("ProcessDue(blocked) unexpected error: %v", err)
	}
	if got := service.PendingMissedTicks(); len(got) != 1 {
		t.Fatalf("missed ticks = %v, want one tick", got)
	}

	lockAvailable = true
	if err := service.ProcessDue(slot.Add(time.Minute)); err != nil {
		t.Fatalf("ProcessDue(replay) unexpected error: %v", err)
	}
	if got := service.PendingMissedTicks(); len(got) != 0 {
		t.Fatalf("missed ticks after replay = %v, want none", got)
	}
	if len(created) != 1 || created[0].Reason != updatePolicyRunReasonMaintenance {
		t.Fatalf("created replay runs = %+v, want one maintenance skip", created)
	}
}

func TestPolicyServicePartialBackupRestoreLockOverridesAreNonLocking(t *testing.T) {
	slot := time.Date(2026, 1, 5, 3, 0, 0, 0, time.UTC)
	baseDeps := testPolicyServiceDeps()
	baseDeps.ListPolicies = func() ([]UpdatePolicy, error) {
		return []UpdatePolicy{{
			ID:            8,
			Name:          "nightly",
			Enabled:       true,
			TargetServers: []string{"srv"},
			PackageScope:  updatePolicyPackageScopeSecurity,
			ExecutionMode: updatePolicyExecutionScanOnly,
			CadenceKind:   updatePolicyCadenceDaily,
			TimeLocal:     "03:00",
		}}, nil
	}
	baseDeps.SnapshotServers = func() []Server {
		return []Server{{Name: "srv"}}
	}
	baseDeps.CurrentStatusSnapshot = func(string) *ServerStatus {
		return &ServerStatus{Name: "srv", Status: "idle"}
	}

	t.Run("try only", func(t *testing.T) {
		deps := baseDeps
		deps.TryBackupRestoreReadLock = func() bool { return true }
		deps.UnlockBackupRestoreRead = nil
		executed := 0
		deps.ExecuteRun = func(UpdatePolicyRun, UpdatePolicy, Server) {
			executed++
		}

		if err := NewPolicyService(deps).ProcessDue(slot); err != nil {
			t.Fatalf("ProcessDue() unexpected error: %v", err)
		}
		if executed != 1 {
			t.Fatalf("executed = %d, want 1", executed)
		}
	})

	t.Run("unlock only", func(t *testing.T) {
		deps := baseDeps
		deps.TryBackupRestoreReadLock = nil
		deps.UnlockBackupRestoreRead = func() {
			t.Fatalf("unlock-only override should not be called")
		}
		executed := 0
		deps.ExecuteRun = func(UpdatePolicyRun, UpdatePolicy, Server) {
			executed++
		}

		if err := NewPolicyService(deps).ProcessDue(slot); err != nil {
			t.Fatalf("ProcessDue() unexpected error: %v", err)
		}
		if executed != 1 {
			t.Fatalf("executed = %d, want 1", executed)
		}
	})
}
