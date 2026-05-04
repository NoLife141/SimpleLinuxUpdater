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

	t.Run("malformed audit metadata leaves facts free space intact", func(t *testing.T) {
		badMetaServer := Server{Name: "srv-bad-meta", Host: "10.0.0.11", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
		mu.Lock()
		servers = append(servers, badMetaServer)
		statusMap[badMetaServer.Name] = &ServerStatus{Name: badMetaServer.Name, Host: badMetaServer.Host, Port: badMetaServer.Port, User: badMetaServer.User, Status: "idle", Tags: badMetaServer.Tags}
		mu.Unlock()

		if err := saveServerFacts(serverFactsRecord{
			ServerName:    badMetaServer.Name,
			CollectedAt:   "not-a-timestamp",
			OSPrettyName:  "Debian GNU/Linux 12",
			UptimeSeconds: 120,
			DiskStatus:    "ok",
			DiskFreeKB:    1024,
			DiskDetails:   "Saved facts disk detail.",
			AptStatus:     "ok",
			AptDetails:    "Saved facts apt detail.",
			RawJSON:       "",
		}); err != nil {
			t.Fatalf("saveServerFacts() error = %v", err)
		}
		if err := writeAuditEvent(AuditEvent{
			CreatedAt:  now.Add(-20 * time.Minute).Format(time.RFC3339),
			Actor:      "tester",
			Action:     updateCompleteAction,
			TargetType: "server",
			TargetName: badMetaServer.Name,
			Status:     "success",
			Message:    "Final status: done",
			MetaJSON:   `{"precheck_results":`,
		}); err != nil {
			t.Fatalf("writeAuditEvent(malformed meta) error = %v", err)
		}

		summary, err := buildDashboardSummary("7d", now)
		if err != nil {
			t.Fatalf("buildDashboardSummary() error = %v", err)
		}
		var found *dashboardServerSummary
		for i := range summary.Servers {
			if summary.Servers[i].Name == badMetaServer.Name {
				found = &summary.Servers[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("summary missing %q", badMetaServer.Name)
		}
		if found.Health.DiskFreeKB != 1024 {
			t.Fatalf("DiskFreeKB = %d, want facts-derived 1024", found.Health.DiskFreeKB)
		}
		if found.LastUpdate == nil || found.LastUpdate.DurationMS != 0 {
			t.Fatalf("LastUpdate = %+v, want successful run without parsed duration", found.LastUpdate)
		}
	})

	t.Run("missing saved facts returns unknown health source", func(t *testing.T) {
		missingFactsServer := Server{Name: "srv-missing-facts", Host: "10.0.0.12", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
		mu.Lock()
		servers = append(servers, missingFactsServer)
		statusMap[missingFactsServer.Name] = &ServerStatus{Name: missingFactsServer.Name, Host: missingFactsServer.Host, Port: missingFactsServer.Port, User: missingFactsServer.User, Status: "idle", Tags: missingFactsServer.Tags}
		mu.Unlock()

		summary, err := buildDashboardSummary("7d", now)
		if err != nil {
			t.Fatalf("buildDashboardSummary() error = %v", err)
		}
		var found *dashboardServerSummary
		for i := range summary.Servers {
			if summary.Servers[i].Name == missingFactsServer.Name {
				found = &summary.Servers[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("summary missing %q", missingFactsServer.Name)
		}
		if found.Health.Source != "unknown" || found.Health.DiskStatus != "unknown" || found.Health.AptStatus != "unknown" {
			t.Fatalf("Health = %+v, want unknown source/statuses", found.Health)
		}
	})
}

func TestUpdateHealthFromResultsLeavesRebootUnknownOnCommandError(t *testing.T) {
	health := dashboardHealthInfo{}
	updateHealthFromResults(&health, []updatePrecheckResult{
		{
			Name:    postcheckNameRebootRequired,
			Passed:  false,
			Details: "failed to evaluate reboot-required state: exit status 1",
			Error:   "exit status 1",
		},
	}, "audit", "2026-05-04T11:00:00Z")

	if health.RebootRequired != nil {
		t.Fatalf("RebootRequired = %v, want nil for command error", *health.RebootRequired)
	}
}

func TestUpdateHealthFromResultsSkipsStaleAuditMetadata(t *testing.T) {
	currentAt := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	staleAt := time.Date(2026, 5, 4, 11, 0, 0, 0, time.UTC).Format(time.RFC3339)
	newerAt := time.Date(2026, 5, 4, 13, 0, 0, 0, time.UTC).Format(time.RFC3339)
	health := dashboardHealthInfo{
		DiskStatus:  "ok",
		DiskFreeKB:  2048,
		DiskDetails: "fresh disk facts",
		AptStatus:   "ok",
		AptDetails:  "fresh apt facts",
		CollectedAt: currentAt,
		Source:      "facts",
	}

	updateHealthFromResults(&health, []updatePrecheckResult{
		{Name: "disk_space", Passed: false, Details: "stale disk audit", Output: "available_kb=1"},
		{Name: "apt_health", Passed: false, Details: "stale apt audit"},
	}, "audit", staleAt)

	if health.Source != "facts" || health.CollectedAt != currentAt {
		t.Fatalf("Health source/time = %s/%s, want facts/%s", health.Source, health.CollectedAt, currentAt)
	}
	if health.DiskStatus != "ok" || health.DiskFreeKB != 2048 || health.DiskDetails != "fresh disk facts" {
		t.Fatalf("Disk health = %s/%d/%q, want fresh facts", health.DiskStatus, health.DiskFreeKB, health.DiskDetails)
	}
	if health.AptStatus != "ok" || health.AptDetails != "fresh apt facts" {
		t.Fatalf("APT health = %s/%q, want fresh facts", health.AptStatus, health.AptDetails)
	}

	updateHealthFromResults(&health, []updatePrecheckResult{
		{Name: "apt_health", Passed: false, Details: "newer apt audit"},
	}, "audit", newerAt)

	if health.AptStatus != "critical" || health.AptDetails != "newer apt audit" {
		t.Fatalf("APT health after newer audit = %s/%q, want newer critical audit", health.AptStatus, health.AptDetails)
	}
	if health.Source != "audit" || health.CollectedAt != newerAt {
		t.Fatalf("Health source/time after newer audit = %s/%s, want audit/%s", health.Source, health.CollectedAt, newerAt)
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

	t.Run("disabled policy is not projected", func(t *testing.T) {
		preserveServerState(t)
		preserveDBState(t)
		t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "dashboard-disabled-policy.db"))
		_ = getDB()
		if _, err := saveAppTimezone("UTC"); err != nil {
			t.Fatalf("saveAppTimezone() error = %v", err)
		}

		server := Server{Name: "srv-disabled-policy", Host: "10.0.0.30", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
		mu.Lock()
		servers = []Server{server}
		statusMap = map[string]*ServerStatus{
			server.Name: {Name: server.Name, Host: server.Host, Port: server.Port, User: server.User, Status: "idle", Tags: server.Tags},
		}
		mu.Unlock()

		if _, err := createUpdatePolicy(UpdatePolicy{
			Name:          "disabled-prod",
			Enabled:       false,
			TargetTag:     "prod",
			PackageScope:  updatePolicyPackageScopeFull,
			ExecutionMode: updatePolicyExecutionAutoApply,
			CadenceKind:   updatePolicyCadenceDaily,
			TimeLocal:     "16:30",
		}); err != nil {
			t.Fatalf("createUpdatePolicy() error = %v", err)
		}
		summary, err := buildDashboardSummary("7d", now)
		if err != nil {
			t.Fatalf("buildDashboardSummary() error = %v", err)
		}
		if got := summary.Servers[0].NextRun.State; got != "none" {
			t.Fatalf("NextRun.State = %q, want none", got)
		}
	})

	t.Run("invalid stored policy time is ignored", func(t *testing.T) {
		preserveServerState(t)
		preserveDBState(t)
		t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "dashboard-invalid-policy.db"))
		_ = getDB()
		if _, err := saveAppTimezone("UTC"); err != nil {
			t.Fatalf("saveAppTimezone() error = %v", err)
		}

		server := Server{Name: "srv-invalid-policy", Host: "10.0.0.31", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
		mu.Lock()
		servers = []Server{server}
		statusMap = map[string]*ServerStatus{
			server.Name: {Name: server.Name, Host: server.Host, Port: server.Port, User: server.User, Status: "idle", Tags: server.Tags},
		}
		mu.Unlock()

		policy, err := createUpdatePolicy(UpdatePolicy{
			Name:          "invalid-time-prod",
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
		if _, err := getDB().Exec("UPDATE update_policies SET time_local = ? WHERE id = ?", "not-time", policy.ID); err != nil {
			t.Fatalf("corrupt policy time_local error = %v", err)
		}
		summary, err := buildDashboardSummary("7d", now)
		if err != nil {
			t.Fatalf("buildDashboardSummary() error = %v", err)
		}
		if got := summary.Servers[0].NextRun.State; got != "none" {
			t.Fatalf("NextRun.State = %q, want none", got)
		}
	})
}

func TestCollectServerFactsWithConnectionParsesHostFacts(t *testing.T) {
	t.Run("parses successful host facts", func(t *testing.T) {
		conn := &scriptedSSHConnection{
			responses: map[string]scriptedResponse{
				serverFactsOSCmd:           {stdout: "Ubuntu 24.04 LTS\n"},
				serverFactsUptimeCmd:       {stdout: "12345.67 100.00\n"},
				precheckDiskSpaceCmd:       {stdout: "2097152\n3145728\n"},
				precheckDpkgAuditCmd:       {},
				precheckAptCheckCmd:        {},
				postcheckRebootRequiredCmd: {stdout: "System restart required\n"},
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
	})

	t.Run("malformed uptime becomes zero", func(t *testing.T) {
		conn := &scriptedSSHConnection{
			responses: map[string]scriptedResponse{
				serverFactsOSCmd:           {stdout: "Ubuntu 24.04 LTS\n"},
				serverFactsUptimeCmd:       {stdout: "not-a-number\n"},
				precheckDiskSpaceCmd:       {stdout: "2097152\n"},
				precheckDpkgAuditCmd:       {},
				precheckAptCheckCmd:        {},
				postcheckRebootRequiredCmd: {},
			},
		}

		got := collectServerFactsWithConnection(Server{Name: "srv-bad-uptime"}, conn, time.Second)
		if got.UptimeSeconds != 0 {
			t.Fatalf("UptimeSeconds = %d, want 0", got.UptimeSeconds)
		}
	})

	t.Run("missing disk output keeps zero free space", func(t *testing.T) {
		conn := &scriptedSSHConnection{
			responses: map[string]scriptedResponse{
				serverFactsOSCmd:           {stdout: "Ubuntu 24.04 LTS\n"},
				serverFactsUptimeCmd:       {stdout: "123.45 100.00\n"},
				precheckDiskSpaceCmd:       {stdout: ""},
				precheckDpkgAuditCmd:       {},
				precheckAptCheckCmd:        {},
				postcheckRebootRequiredCmd: {},
			},
		}

		got := collectServerFactsWithConnection(Server{Name: "srv-missing-disk"}, conn, time.Second)
		if got.DiskFreeKB != 0 {
			t.Fatalf("DiskFreeKB = %d, want 0", got.DiskFreeKB)
		}
		if got.AptStatus != "ok" {
			t.Fatalf("AptStatus = %q, want ok", got.AptStatus)
		}
	})

	t.Run("generic reboot command failure is not reboot required", func(t *testing.T) {
		conn := &scriptedSSHConnection{
			responses: map[string]scriptedResponse{
				serverFactsOSCmd:           {stdout: "Ubuntu 24.04 LTS\n"},
				serverFactsUptimeCmd:       {stdout: "123.45 100.00\n"},
				precheckDiskSpaceCmd:       {stdout: "2097152\n"},
				precheckDpkgAuditCmd:       {},
				precheckAptCheckCmd:        {},
				postcheckRebootRequiredCmd: {stderr: "failed to check reboot state\n", err: fakeExitStatusError{code: 1}},
			},
		}

		got := collectServerFactsWithConnection(Server{Name: "srv-reboot-error"}, conn, time.Second)
		if got.RebootRequired == nil || *got.RebootRequired {
			t.Fatalf("RebootRequired = %v, want false", got.RebootRequired)
		}
	})

	t.Run("non reboot marker output is not reboot required", func(t *testing.T) {
		conn := &scriptedSSHConnection{
			responses: map[string]scriptedResponse{
				serverFactsOSCmd:           {stdout: "Ubuntu 24.04 LTS\n"},
				serverFactsUptimeCmd:       {stdout: "123.45 100.00\n"},
				precheckDiskSpaceCmd:       {stdout: "2097152\n"},
				precheckDpkgAuditCmd:       {},
				precheckAptCheckCmd:        {},
				postcheckRebootRequiredCmd: {stdout: "12345\n"},
			},
		}

		got := collectServerFactsWithConnection(Server{Name: "srv-reboot-numeric"}, conn, time.Second)
		if got.RebootRequired == nil || *got.RebootRequired {
			t.Fatalf("RebootRequired = %v, want false", got.RebootRequired)
		}
	})
}
