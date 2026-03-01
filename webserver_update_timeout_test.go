package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type slowSSHConnection struct {
	delay    time.Duration
	runErr   error
	commands []string
	mu       sync.Mutex
}

type slowSSHSession struct {
	conn   *slowSSHConnection
	stdout io.Writer
	stderr io.Writer
}

func (s *slowSSHSession) SetStdin(io.Reader) {}

func (s *slowSSHSession) SetStdout(w io.Writer) { s.stdout = w }

func (s *slowSSHSession) SetStderr(w io.Writer) { s.stderr = w }

func (s *slowSSHSession) Run(cmd string) error {
	s.conn.mu.Lock()
	s.conn.commands = append(s.conn.commands, cmd)
	s.conn.mu.Unlock()
	time.Sleep(s.conn.delay)
	return s.conn.runErr
}

func (s *slowSSHSession) Close() error { return nil }

func (c *slowSSHConnection) NewSession() (sshSessionRunner, error) {
	return &slowSSHSession{conn: c}, nil
}

func (c *slowSSHConnection) Close() error { return nil }

func setupTimeoutRunnerEnv(t *testing.T, dbName string) {
	t.Helper()
	preserveServerState(t)
	preserveDBState(t)
	t.Setenv(retryMaxAttemptsEnv, "1")
	t.Setenv(sshCommandTimeoutSecondsEnv, "1")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), dbName))
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)
}

func TestRunUpdateWithActorCommandTimeoutSetsError(t *testing.T) {
	setupTimeoutRunnerEnv(t, "update-timeout.db")
	t.Setenv(postchecksEnabledEnv, "false")

	server := Server{Name: "srv-update-timeout", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd:    {stdout: "2048000\n2097152\n"},
			precheckLocksCmd:        {err: fakeExitStatusError{code: 1, msg: "no process found"}},
			precheckDpkgAuditCmd:    {},
			precheckAptCheckCmd:     {},
			postcheckFailedUnitsCmd: {},
			aptUpdateCmd:            {delay: 3 * time.Second},
		},
	}
	origDial := dialSSHConnection
	dialSSHConnection = func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		return conn, nil
	}
	t.Cleanup(func() { dialSSHConnection = origDial })

	runUpdateWithActor(server, "tester", "127.0.0.1", loadRetryPolicyFromEnv())

	mu.Lock()
	finalStatus := statusMap[server.Name].Status
	logs := statusMap[server.Name].Logs
	mu.Unlock()
	if finalStatus != "error" {
		t.Fatalf("final status = %q, want error", finalStatus)
	}
	if !strings.Contains(strings.ToLower(logs), "timed out") {
		t.Fatalf("expected timeout in logs, got: %s", logs)
	}

	var metaJSON string
	if err := db.QueryRow("SELECT meta_json FROM audit_events WHERE action = ? AND target_name = ? ORDER BY id DESC LIMIT 1", updateCompleteAction, server.Name).Scan(&metaJSON); err != nil {
		t.Fatalf("query audit metadata: %v", err)
	}
	meta := map[string]any{}
	if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
		t.Fatalf("parse audit metadata: %v", err)
	}
	if got, ok := meta["last_error_class"].(string); !ok || got != "transient" {
		t.Fatalf("last_error_class = %v, want transient", meta["last_error_class"])
	}
	if got, ok := meta["retry_exhausted"].(bool); !ok || !got {
		t.Fatalf("retry_exhausted = %v, want true", meta["retry_exhausted"])
	}
}

func TestRunAutoremoveWithActorCommandTimeoutSetsError(t *testing.T) {
	setupTimeoutRunnerEnv(t, "autoremove-timeout.db")

	server := Server{Name: "srv-autoremove-timeout", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	conn := &slowSSHConnection{delay: 3 * time.Second}
	origDial := dialSSHConnection
	dialSSHConnection = func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		return conn, nil
	}
	t.Cleanup(func() { dialSSHConnection = origDial })

	runAutoremoveWithActor(server, "tester", "127.0.0.1", loadRetryPolicyFromEnv())

	mu.Lock()
	finalStatus := statusMap[server.Name].Status
	logs := statusMap[server.Name].Logs
	mu.Unlock()
	if finalStatus != "error" {
		t.Fatalf("final status = %q, want error", finalStatus)
	}
	if !strings.Contains(strings.ToLower(logs), "timed out") {
		t.Fatalf("expected timeout in logs, got: %s", logs)
	}
}

func TestRunSudoersBootstrapWithActorCommandTimeoutSetsError(t *testing.T) {
	setupTimeoutRunnerEnv(t, "sudoers-enable-timeout.db")

	server := Server{Name: "srv-sudoers-enable-timeout", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	conn := &slowSSHConnection{delay: 3 * time.Second}
	origDial := dialSSHConnection
	dialSSHConnection = func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		return conn, nil
	}
	t.Cleanup(func() { dialSSHConnection = origDial })

	runSudoersBootstrapWithActor(server, "pw", "tester", "127.0.0.1", loadRetryPolicyFromEnv())

	mu.Lock()
	finalStatus := statusMap[server.Name].Status
	logs := statusMap[server.Name].Logs
	mu.Unlock()
	if finalStatus != "error" {
		t.Fatalf("final status = %q, want error", finalStatus)
	}
	if !strings.Contains(strings.ToLower(logs), "timed out") {
		t.Fatalf("expected timeout in logs, got: %s", logs)
	}
}

func TestRunSudoersDisableWithActorCommandTimeoutSetsError(t *testing.T) {
	setupTimeoutRunnerEnv(t, "sudoers-disable-timeout.db")

	server := Server{Name: "srv-sudoers-disable-timeout", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	conn := &slowSSHConnection{delay: 3 * time.Second}
	origDial := dialSSHConnection
	dialSSHConnection = func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		return conn, nil
	}
	t.Cleanup(func() { dialSSHConnection = origDial })

	runSudoersDisableWithActor(server, "pw", "tester", "127.0.0.1", loadRetryPolicyFromEnv())

	mu.Lock()
	finalStatus := statusMap[server.Name].Status
	logs := statusMap[server.Name].Logs
	mu.Unlock()
	if finalStatus != "error" {
		t.Fatalf("final status = %q, want error", finalStatus)
	}
	if !strings.Contains(strings.ToLower(logs), "timed out") {
		t.Fatalf("expected timeout in logs, got: %s", logs)
	}
}
