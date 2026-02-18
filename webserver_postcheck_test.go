package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestLoadPostUpdateCheckConfigFromEnv(t *testing.T) {
	t.Setenv(postchecksEnabledEnv, "true")
	t.Setenv(postcheckBlockOnAptHealthEnv, "true")
	t.Setenv(postcheckBlockOnFailedUnitsEnv, "true")
	t.Setenv(postcheckRebootRequiredWarningEnv, "true")
	t.Setenv(postcheckCustomCmdEnv, "")

	defaults := loadPostUpdateCheckConfigFromEnv()
	if !defaults.Enabled || !defaults.BlockOnAptHealth || !defaults.BlockOnFailedUnits || !defaults.RebootRequiredWarning {
		t.Fatalf("unexpected default-like config: %+v", defaults)
	}

	t.Setenv(postchecksEnabledEnv, "false")
	t.Setenv(postcheckBlockOnAptHealthEnv, "false")
	t.Setenv(postcheckBlockOnFailedUnitsEnv, "false")
	t.Setenv(postcheckRebootRequiredWarningEnv, "false")
	t.Setenv(postcheckCustomCmdEnv, "  /usr/local/bin/health-check --quick  ")

	cfg := loadPostUpdateCheckConfigFromEnv()
	if cfg.Enabled || cfg.BlockOnAptHealth || cfg.BlockOnFailedUnits || cfg.RebootRequiredWarning {
		t.Fatalf("config booleans not parsed as expected: %+v", cfg)
	}
	if cfg.CustomCommand != "/usr/local/bin/health-check --quick" {
		t.Fatalf("CustomCommand = %q, want trimmed value", cfg.CustomCommand)
	}
}

func TestRunPostUpdateHealthChecksWarningOnlyReboot(t *testing.T) {
	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDpkgAuditCmd:       {},
			precheckAptCheckCmd:        {},
			postcheckFailedUnitsCmd:    {},
			postcheckRebootRequiredCmd: {stdout: "required\n"},
		},
	}
	summary := runPostUpdateHealthChecks(conn, PostUpdateCheckConfig{
		Enabled:               true,
		BlockOnAptHealth:      true,
		BlockOnFailedUnits:    true,
		RebootRequiredWarning: true,
	})
	if !summary.AllPassed {
		t.Fatalf("runPostUpdateHealthChecks() AllPassed = false, want true for warning-only reboot: %+v", summary)
	}
	if summary.Warnings != 1 {
		t.Fatalf("Warnings = %d, want 1", summary.Warnings)
	}
	if summary.FailedCheck != "" {
		t.Fatalf("FailedCheck = %q, want empty", summary.FailedCheck)
	}
}

func TestRunPostUpdateHealthChecksBlockingFailedUnits(t *testing.T) {
	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDpkgAuditCmd:    {},
			precheckAptCheckCmd:     {},
			postcheckFailedUnitsCmd: {stdout: "ssh.service loaded failed failed\n"},
		},
	}
	summary := runPostUpdateHealthChecks(conn, PostUpdateCheckConfig{
		Enabled:               true,
		BlockOnAptHealth:      true,
		BlockOnFailedUnits:    true,
		RebootRequiredWarning: false,
	})
	if summary.AllPassed {
		t.Fatalf("runPostUpdateHealthChecks() AllPassed = true, want false")
	}
	if summary.FailedCheck != postcheckNameFailedUnits {
		t.Fatalf("FailedCheck = %q, want %q", summary.FailedCheck, postcheckNameFailedUnits)
	}
}

func TestRunPostUpdateHealthChecksBlockingCustomCommand(t *testing.T) {
	customCmd := "sudo /usr/local/bin/health-check"
	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDpkgAuditCmd:    {},
			precheckAptCheckCmd:     {},
			postcheckFailedUnitsCmd: {},
			customCmd:               {err: fakeExitStatusError{code: 1, msg: "exit status 1"}, stderr: "health endpoint failed"},
		},
	}
	summary := runPostUpdateHealthChecks(conn, PostUpdateCheckConfig{
		Enabled:               true,
		BlockOnAptHealth:      true,
		BlockOnFailedUnits:    true,
		RebootRequiredWarning: false,
		CustomCommand:         customCmd,
	})
	if summary.AllPassed {
		t.Fatalf("runPostUpdateHealthChecks() AllPassed = true, want false")
	}
	if summary.FailedCheck != postcheckNameCustomCmd {
		t.Fatalf("FailedCheck = %q, want %q", summary.FailedCheck, postcheckNameCustomCmd)
	}
}

func TestRunUpdateWithActorPostcheckBlockingFailureSetsError(t *testing.T) {
	preserveServerState(t)
	preserveDBState(t)

	t.Setenv(retryMaxAttemptsEnv, "1")
	t.Setenv(postchecksEnabledEnv, "true")
	t.Setenv(postcheckBlockOnAptHealthEnv, "true")
	t.Setenv(postcheckBlockOnFailedUnitsEnv, "true")
	t.Setenv(postcheckRebootRequiredWarningEnv, "true")
	t.Setenv(postcheckCustomCmdEnv, "")

	dbFile := filepath.Join(t.TempDir(), "postcheck.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)

	server := Server{Name: "srv-postcheck-fail", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd:       {stdout: "2048000\n2097152\n"},
			precheckLocksCmd:           {err: fakeExitStatusError{code: 1, msg: "no process found"}},
			precheckDpkgAuditCmd:       {},
			precheckAptCheckCmd:        {},
			"sudo apt update":          {},
			"apt list --upgradable":    {stdout: "Listing...\npkg/stable 1.2 amd64 [upgradable from: 1.1]\n"},
			"sudo apt upgrade -y":      {},
			postcheckFailedUnitsCmd:    {stdout: "ssh.service loaded failed failed\n"},
			postcheckRebootRequiredCmd: {},
		},
	}
	origDial := dialSSHConnection
	dialSSHConnection = func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		return conn, nil
	}
	t.Cleanup(func() { dialSSHConnection = origDial })

	done := make(chan struct{})
	go func() {
		runUpdateWithActor(server, "tester", "127.0.0.1", loadRetryPolicyFromEnv())
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		status := statusMap[server.Name]
		pending := status != nil && status.Status == "pending_approval"
		mu.Unlock()
		if pending {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	if status := statusMap[server.Name]; status != nil && status.Status == "pending_approval" {
		status.Status = "approved"
	}
	mu.Unlock()

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for update flow")
	}

	mu.Lock()
	finalStatus := statusMap[server.Name].Status
	logs := statusMap[server.Name].Logs
	mu.Unlock()
	if finalStatus != "error" {
		t.Fatalf("final status = %q, want error", finalStatus)
	}
	if !strings.Contains(logs, "Upgrade completed but post-check failed (failed_units).") {
		t.Fatalf("expected post-check failure log, got: %s", logs)
	}

	var metaJSON string
	if err := db.QueryRow("SELECT meta_json FROM audit_events WHERE action = ? AND target_name = ? ORDER BY id DESC LIMIT 1", "update.complete", server.Name).Scan(&metaJSON); err != nil {
		t.Fatalf("query audit metadata: %v", err)
	}
	meta := map[string]any{}
	if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
		t.Fatalf("parse audit metadata: %v", err)
	}
	if got, ok := meta["postcheck_failed"].(string); !ok || got != postcheckNameFailedUnits {
		t.Fatalf("postcheck_failed = %v, want %q", meta["postcheck_failed"], postcheckNameFailedUnits)
	}
}
