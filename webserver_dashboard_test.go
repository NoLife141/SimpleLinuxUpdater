package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func mustDashboardMeta(t *testing.T, meta map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(raw)
}

func TestBuildDashboardSummaryAggregatesIntelligence(t *testing.T) {
	preserveServerState(t)
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "dashboard.db"))
	_ = getDB()

	now := time.Date(2026, 4, 29, 15, 0, 0, 0, time.UTC)
	server := Server{Name: "srv-a", Host: "10.0.0.10", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {
			Name:   server.Name,
			Host:   server.Host,
			Port:   server.Port,
			User:   server.User,
			Status: "pending_approval",
			PendingUpdates: []PendingUpdate{
				{Package: "openssl", Security: true, CVEs: []string{"CVE-2026-0001"}, CVEState: "ready"},
				{Package: "bash", Security: false, CVEState: "ready"},
			},
			Tags: server.Tags,
		},
	}
	mu.Unlock()

	rebootRequired := false
	if err := saveServerFacts(serverFactsRecord{
		ServerName:     server.Name,
		CollectedAt:    now.Add(-2 * time.Hour).Format(time.RFC3339),
		OSPrettyName:   "Debian GNU/Linux 12",
		UptimeSeconds:  86400,
		DiskStatus:     "ok",
		DiskFreeKB:     4 * 1024 * 1024,
		DiskDetails:    "Enough free disk space.",
		AptStatus:      "ok",
		AptDetails:     "APT health checks passed.",
		RebootRequired: &rebootRequired,
		RawJSON:        "{}",
	}); err != nil {
		t.Fatalf("saveServerFacts() error = %v", err)
	}

	if err := writeAuditEvent(AuditEvent{
		CreatedAt:  now.Add(-90 * time.Minute).Format(time.RFC3339),
		Actor:      "tester",
		Action:     updateCompleteAction,
		TargetType: "server",
		TargetName: server.Name,
		Status:     "success",
		Message:    "Final status: done",
		MetaJSON: mustDashboardMeta(t, map[string]any{
			"execution_duration_ms": 2400,
			"precheck_results": []updatePrecheckResult{
				{Name: "disk_space", Passed: true, Details: "Enough free disk space.", Output: "4194304\n5242880\n"},
				{Name: "apt_health", Passed: true, Details: "APT health checks passed."},
			},
			"postcheck_results": []updatePrecheckResult{
				{Name: postcheckNameRebootRequired, Passed: false, Details: "Reboot required to fully apply updates."},
			},
		}),
	}); err != nil {
		t.Fatalf("writeAuditEvent(success) error = %v", err)
	}
	if err := writeAuditEvent(AuditEvent{
		CreatedAt:  now.Add(-30 * time.Minute).Format(time.RFC3339),
		Actor:      "tester",
		Action:     "server.facts.refresh",
		TargetType: "server",
		TargetName: server.Name,
		Status:     "success",
		Message:    "Host facts refreshed",
		MetaJSON:   "{}",
	}); err != nil {
		t.Fatalf("writeAuditEvent(command) error = %v", err)
	}

	summary, err := buildDashboardSummary("7d", now)
	if err != nil {
		t.Fatalf("buildDashboardSummary() error = %v", err)
	}
	if len(summary.Servers) != 1 {
		t.Fatalf("len(summary.Servers) = %d, want 1", len(summary.Servers))
	}
	got := summary.Servers[0]
	if got.Name != server.Name {
		t.Fatalf("server name = %q, want %q", got.Name, server.Name)
	}
	if got.LastUpdate == nil || got.LastUpdate.DurationMS != 2400 {
		t.Fatalf("LastUpdate = %+v, want duration 2400", got.LastUpdate)
	}
	if got.AvgDurationMS != 2400 || got.DurationSamples != 1 {
		t.Fatalf("AvgDurationMS/Samples = %.0f/%d, want 2400/1", got.AvgDurationMS, got.DurationSamples)
	}
	if got.Risk.Level != "critical" || len(got.Risk.CVEs) != 1 {
		t.Fatalf("risk = %+v, want critical with one CVE", got.Risk)
	}
	if got.Health.RebootRequired == nil || !*got.Health.RebootRequired {
		t.Fatalf("reboot required = %v, want true from postcheck metadata", got.Health.RebootRequired)
	}
	if got.Health.OSPrettyName != "Debian GNU/Linux 12" || got.Health.UptimeSeconds != 86400 {
		t.Fatalf("facts = %+v, want saved OS/uptime facts", got.Health)
	}
	if len(got.CommandHistory) == 0 {
		t.Fatalf("CommandHistory empty, want recent server command")
	}
	if got.NextRun.State != "none" {
		t.Fatalf("NextRun.State = %q, want none", got.NextRun.State)
	}
}

func TestBuildDashboardSummaryProjectsFuturePolicyRun(t *testing.T) {
	preserveServerState(t)
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "dashboard-next-run.db"))
	_ = getDB()
	if _, err := saveAppTimezone("UTC"); err != nil {
		t.Fatalf("saveAppTimezone() error = %v", err)
	}

	now := time.Date(2026, 4, 29, 15, 0, 0, 0, time.UTC)
	server := Server{Name: "srv-scheduled", Host: "10.0.0.20", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Host: server.Host, Port: server.Port, User: server.User, Status: "idle", Tags: server.Tags},
	}
	mu.Unlock()

	policy, err := createUpdatePolicy(UpdatePolicy{
		Name:          "daily-prod",
		Enabled:       true,
		TargetTag:     "prod",
		PackageScope:  updatePolicyPackageScopeFull,
		ExecutionMode: updatePolicyExecutionAutoApply,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     "16:30",
	})
	if err != nil {
		t.Fatalf("createUpdatePolicy() error = %v", err)
	}

	summary, err := buildDashboardSummary("7d", now)
	if err != nil {
		t.Fatalf("buildDashboardSummary() error = %v", err)
	}
	if len(summary.Servers) != 1 {
		t.Fatalf("len(summary.Servers) = %d, want 1", len(summary.Servers))
	}
	got := summary.Servers[0].NextRun
	wantScheduled := time.Date(2026, 4, 29, 16, 30, 0, 0, time.UTC).Format(jobTimestampLayout)
	if got.State != "scheduled" || got.PolicyName != policy.Name || got.ScheduledForUTC != wantScheduled {
		t.Fatalf("NextRun = %+v, want projected policy %q at %s", got, policy.Name, wantScheduled)
	}

	runs, err := listUpdatePolicyRuns(10)
	if err != nil {
		t.Fatalf("listUpdatePolicyRuns() error = %v", err)
	}
	if len(runs) != 0 {
		t.Fatalf("materialized run count = %d, want 0 before due time", len(runs))
	}
}

func TestCollectServerFactsWithConnectionParsesHostFacts(t *testing.T) {
	rebootText := "required\n"
	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			serverFactsOSCmd:           {stdout: "Ubuntu 24.04 LTS\n"},
			serverFactsUptimeCmd:       {stdout: "12345.67 100.00\n"},
			precheckDiskSpaceCmd:       {stdout: "2097152\n3145728\n"},
			precheckDpkgAuditCmd:       {},
			precheckAptCheckCmd:        {},
			postcheckRebootRequiredCmd: {stdout: rebootText},
		},
	}

	got := collectServerFactsWithConnection(Server{Name: "srv-facts"}, conn, time.Second)
	if got.OSPrettyName != "Ubuntu 24.04 LTS" {
		t.Fatalf("OSPrettyName = %q, want Ubuntu 24.04 LTS", got.OSPrettyName)
	}
	if got.UptimeSeconds != 12345 {
		t.Fatalf("UptimeSeconds = %d, want 12345", got.UptimeSeconds)
	}
	if got.DiskStatus != "ok" || got.DiskFreeKB != 2097152 {
		t.Fatalf("disk = %s/%d, want ok/2097152", got.DiskStatus, got.DiskFreeKB)
	}
	if got.AptStatus != "ok" {
		t.Fatalf("AptStatus = %q, want ok", got.AptStatus)
	}
	if got.RebootRequired == nil || !*got.RebootRequired {
		t.Fatalf("RebootRequired = %v, want true", got.RebootRequired)
	}
}
