package policies

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestRepository(t *testing.T) (*SQLiteRepository, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", t.TempDir()+"/policies.db")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create settings table: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema() error = %v", err)
	}
	repo := NewSQLiteRepository(SQLiteRepositoryDeps{
		DB:          func() *sql.DB { return db },
		NowString:   func() string { return "2026-01-02T03:04:05.000000000Z" },
		MarshalJSON: marshalJSON,
	})
	return repo, db
}

func TestSQLiteRepositoryPolicyCRUDOverridesAndRuns(t *testing.T) {
	repo, _ := newTestRepository(t)
	policy, err := repo.CreatePolicy(Policy{
		Name:            "Nightly",
		Enabled:         true,
		TargetServers:   []string{"srv-a"},
		PackageScope:    PackageScopeSecurity,
		ExecutionMode:   ExecutionScanOnly,
		CadenceKind:     CadenceDaily,
		TimeLocal:       "03:00",
		Weekdays:        []string{},
		PolicyBlackouts: []BlackoutWindow{},
	})
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}
	if policy.ID == 0 || policy.Name != "Nightly" || len(policy.TargetServers) != 1 {
		t.Fatalf("CreatePolicy() = %+v, want persisted policy", policy)
	}

	policy.Name = "Morning"
	updated, err := repo.UpdatePolicy(policy.ID, policy)
	if err != nil {
		t.Fatalf("UpdatePolicy() error = %v", err)
	}
	if updated.Name != "Morning" {
		t.Fatalf("UpdatePolicy().Name = %q, want Morning", updated.Name)
	}

	override, err := repo.SetOverride(policy.ID, "srv-a", true)
	if err != nil {
		t.Fatalf("SetOverride(true) error = %v", err)
	}
	if !override.Disabled {
		t.Fatalf("override.Disabled = false, want true")
	}
	allOverrides, err := repo.LoadAllOverrides()
	if err != nil {
		t.Fatalf("LoadAllOverrides() error = %v", err)
	}
	if !allOverrides[policy.ID]["srv-a"] {
		t.Fatalf("LoadAllOverrides() = %+v, want disabled override", allOverrides)
	}

	run, inserted, err := repo.CreateRun(Run{
		PolicyID:        policy.ID,
		PolicyName:      policy.Name,
		ServerName:      "srv-a",
		ScheduledForUTC: "2026-01-02T03:00:00.000000000Z",
		ExecutionMode:   ExecutionScanOnly,
		PackageScope:    PackageScopeSecurity,
	})
	if err != nil || !inserted {
		t.Fatalf("CreateRun() = (%+v, %t, %v), want inserted", run, inserted, err)
	}
	summary := "done"
	status := RunSucceeded
	if err := repo.UpdateRun(run.ID, RunUpdate{Status: &status, Summary: &summary}); err != nil {
		t.Fatalf("UpdateRun() error = %v", err)
	}
	gotRun, err := repo.GetRun(run.ID)
	if err != nil {
		t.Fatalf("GetRun() error = %v", err)
	}
	if gotRun.Status != RunSucceeded || gotRun.Summary != "done" {
		t.Fatalf("GetRun() = %+v, want updated status/summary", gotRun)
	}
}

func TestSQLiteRepositoryGlobalBlackoutsRoundTrip(t *testing.T) {
	repo, _ := newTestRepository(t)
	windows, err := repo.SaveGlobalBlackouts([]BlackoutWindow{{
		Weekdays:  []string{"Monday"},
		StartTime: "22:00",
		EndTime:   "02:00",
	}})
	if err != nil {
		t.Fatalf("SaveGlobalBlackouts() error = %v", err)
	}
	if windows[0].Weekdays[0] != "mon" {
		t.Fatalf("normalized weekday = %q, want mon", windows[0].Weekdays[0])
	}
	loaded, err := repo.LoadGlobalBlackouts()
	if err != nil {
		t.Fatalf("LoadGlobalBlackouts() error = %v", err)
	}
	if len(loaded) != 1 || loaded[0].StartTime != "22:00" || loaded[0].EndTime != "02:00" {
		t.Fatalf("LoadGlobalBlackouts() = %+v", loaded)
	}
}
