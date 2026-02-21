package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

type fakeExitStatusError struct {
	code int
	msg  string
}

func (e fakeExitStatusError) Error() string {
	if strings.TrimSpace(e.msg) != "" {
		return e.msg
	}
	return "exit status"
}

func (e fakeExitStatusError) ExitStatus() int { return e.code }

type scriptedResponse struct {
	stdout string
	stderr string
	err    error
}

type scriptedSSHConnection struct {
	responses         map[string]scriptedResponse
	sequenceResponses map[string][]scriptedResponse
	commandCalls      map[string]int
	commands          []string
	closed            bool
	mu                sync.Mutex
}

func (c *scriptedSSHConnection) NewSession() (sshSessionRunner, error) {
	return &scriptedSSHSession{conn: c}, nil
}

func (c *scriptedSSHConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

type scriptedSSHSession struct {
	conn   *scriptedSSHConnection
	stdout io.Writer
	stderr io.Writer
}

func (s *scriptedSSHSession) SetStdin(io.Reader) {}

func (s *scriptedSSHSession) SetStdout(w io.Writer) { s.stdout = w }

func (s *scriptedSSHSession) SetStderr(w io.Writer) { s.stderr = w }

func (s *scriptedSSHSession) Run(cmd string) error {
	s.conn.mu.Lock()
	defer s.conn.mu.Unlock()

	s.conn.commands = append(s.conn.commands, cmd)
	if seq, ok := s.conn.sequenceResponses[cmd]; ok && len(seq) > 0 {
		if s.conn.commandCalls == nil {
			s.conn.commandCalls = make(map[string]int)
		}
		idx := s.conn.commandCalls[cmd]
		s.conn.commandCalls[cmd] = idx + 1
		if idx >= len(seq) {
			idx = len(seq) - 1
		}
		resp := seq[idx]
		if s.stdout != nil && resp.stdout != "" {
			_, _ = io.WriteString(s.stdout, resp.stdout)
		}
		if s.stderr != nil && resp.stderr != "" {
			_, _ = io.WriteString(s.stderr, resp.stderr)
		}
		return resp.err
	}
	resp, ok := s.conn.responses[cmd]
	if !ok {
		return errors.New("unexpected command: " + cmd)
	}
	if s.stdout != nil && resp.stdout != "" {
		_, _ = io.WriteString(s.stdout, resp.stdout)
	}
	if s.stderr != nil && resp.stderr != "" {
		_, _ = io.WriteString(s.stderr, resp.stderr)
	}
	return resp.err
}

func (s *scriptedSSHSession) Close() error { return nil }

func TestCheckDiskSpacePassAndFail(t *testing.T) {
	passConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "2048000\n2097152\n"},
		},
	}
	if got := checkDiskSpace(passConn); !got.Passed {
		t.Fatalf("checkDiskSpace(pass) = failed, got %+v", got)
	}

	failConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "1024\n2097152\n"},
		},
	}
	if got := checkDiskSpace(failConn); got.Passed {
		t.Fatalf("checkDiskSpace(low free space) = passed, want fail")
	}
}

func TestCheckDiskSpaceMalformedOutput(t *testing.T) {
	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "not-a-number\n"},
		},
	}
	if got := checkDiskSpace(conn); got.Passed {
		t.Fatalf("checkDiskSpace(malformed output) = passed, want fail")
	}
}

func TestCheckAptLocks(t *testing.T) {
	lockedConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckLocksCmd: {},
		},
	}
	if got := checkAptLocks(lockedConn); got.Passed {
		t.Fatalf("checkAptLocks(lock present) = passed, want fail")
	}

	unlockedConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckLocksCmd: {err: fakeExitStatusError{code: 1, msg: "no process found"}},
		},
	}
	if got := checkAptLocks(unlockedConn); !got.Passed {
		t.Fatalf("checkAptLocks(no lock) = failed, got %+v", got)
	}

	unlockedSilentConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckLocksCmd: {err: fakeExitStatusError{code: 1}},
		},
	}
	if got := checkAptLocks(unlockedSilentConn); !got.Passed {
		t.Fatalf("checkAptLocks(no lock, silent output) = failed, got %+v", got)
	}

	sudoPolicyConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckLocksCmd: {
				stderr: "sudo: a password is required\n",
				err:    fakeExitStatusError{code: 1, msg: "exit status 1"},
			},
		},
	}
	if got := checkAptLocks(sudoPolicyConn); got.Passed {
		t.Fatalf("checkAptLocks(sudo password required) = passed, want fail")
	}

	commandNotFoundConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckLocksCmd: {
				stderr: "sudo: /usr/bin/fuser: command not found\n",
				err:    fakeExitStatusError{code: 1, msg: "exit status 1"},
			},
			precheckLocksFallbackCmd: {err: fakeExitStatusError{code: 1, msg: "no process found"}},
		},
	}
	if got := checkAptLocks(commandNotFoundConn); !got.Passed {
		t.Fatalf("checkAptLocks(command not found via sudo, no apt/dpkg processes) = failed, got %+v", got)
	}

	commandNotFoundNoSuchFileConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckLocksCmd: {
				stderr: "sudo: unable to execute /usr/bin/fuser: No such file or directory\n",
				err:    fakeExitStatusError{code: 1, msg: "exit status 1"},
			},
			precheckLocksFallbackCmd: {},
		},
	}
	if got := checkAptLocks(commandNotFoundNoSuchFileConn); got.Passed {
		t.Fatalf("checkAptLocks(missing fuser binary, fallback detects apt/dpkg activity) = passed, want fail")
	}

	missingLockFileConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckLocksCmd: {
				stderr: "/usr/bin/fuser: /var/cache/apt/archives/lock: No such file or directory\n",
				err:    fakeExitStatusError{code: 1, msg: "exit status 1"},
			},
		},
	}
	if got := checkAptLocks(missingLockFileConn); !got.Passed {
		t.Fatalf("checkAptLocks(missing lock file path) = failed, got %+v", got)
	}

	errorConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckLocksCmd: {err: fakeExitStatusError{code: 127, msg: "fuser: not found"}},
			precheckLocksFallbackCmd: {
				err:    fakeExitStatusError{code: 127, msg: "pgrep: not found"},
				stderr: "sh: 1: pgrep: not found\n",
			},
		},
	}
	if got := checkAptLocks(errorConn); got.Passed {
		t.Fatalf("checkAptLocks(command error with failed fallback) = passed, want fail")
	}
}

func TestCheckAptHealth(t *testing.T) {
	dpkgIssueConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDpkgAuditCmd: {stdout: "packages need configuration\n"},
		},
	}
	if got := checkAptHealth(dpkgIssueConn); got.Passed {
		t.Fatalf("checkAptHealth(dpkg issues) = passed, want fail")
	}

	aptCheckFailConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDpkgAuditCmd: {},
			precheckAptCheckCmd:  {err: errors.New("exit status 100"), stderr: "unmet dependencies"},
		},
	}
	if got := checkAptHealth(aptCheckFailConn); got.Passed {
		t.Fatalf("checkAptHealth(apt-get check fails) = passed, want fail")
	}

	okConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDpkgAuditCmd: {},
			precheckAptCheckCmd:  {},
		},
	}
	if got := checkAptHealth(okConn); !got.Passed {
		t.Fatalf("checkAptHealth(clean host) = failed, got %+v", got)
	}
}

func TestRunUpdatePrechecksStopOnFirstFailure(t *testing.T) {
	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "1024\n2048000\n"},
		},
	}
	summary := runUpdatePrechecks(conn)
	if summary.AllPassed {
		t.Fatalf("runUpdatePrechecks() AllPassed = true, want false")
	}
	if summary.FailedCheck != "disk_space" {
		t.Fatalf("FailedCheck = %q, want disk_space", summary.FailedCheck)
	}
	if len(conn.commands) != 1 || conn.commands[0] != precheckDiskSpaceCmd {
		t.Fatalf("expected only disk pre-check command, got %v", conn.commands)
	}
}

func TestRunUpdateWithActorPrecheckFailureStopsBeforeAptUpdate(t *testing.T) {
	preserveServerState(t)
	preserveDBState(t)

	dbFile := filepath.Join(t.TempDir(), "precheck.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)

	server := Server{Name: "srv-precheck-fail", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "1024\n2048000\n"},
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
	if !strings.Contains(logs, "Pre-check failed (disk_space)") {
		t.Fatalf("missing pre-check failure log, got: %s", logs)
	}
	for _, cmd := range conn.commands {
		if cmd == aptUpdateCmd {
			t.Fatalf("apt update executed despite pre-check failure")
		}
	}

	db := getDB()
	var metaJSON string
	if err := db.QueryRow("SELECT meta_json FROM audit_events WHERE action = ? AND target_name = ? ORDER BY id DESC LIMIT 1", "update.complete", server.Name).Scan(&metaJSON); err != nil {
		t.Fatalf("query audit metadata: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
		t.Fatalf("parse audit metadata: %v", err)
	}
	if _, ok := meta["prechecks_passed"]; !ok {
		t.Fatalf("missing prechecks_passed in audit metadata: %v", meta)
	}
	if _, ok := meta["precheck_failed"]; !ok {
		t.Fatalf("missing precheck_failed in audit metadata: %v", meta)
	}
	if _, ok := meta["precheck_results"]; !ok {
		t.Fatalf("missing precheck_results in audit metadata: %v", meta)
	}
	totalElapsedMS, ok := meta["total_elapsed_ms"].(float64)
	if !ok {
		t.Fatalf("missing total_elapsed_ms in audit metadata: %v", meta)
	}
	if totalElapsedMS < 0 {
		t.Fatalf("total_elapsed_ms = %v, want >= 0", totalElapsedMS)
	}
	if _, ok := meta["execution_duration_ms"]; ok {
		t.Fatalf("execution_duration_ms should not be set before approval: %v", meta)
	}
}
