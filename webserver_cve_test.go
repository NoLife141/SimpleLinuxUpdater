package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func changelogCVECommand(pkg string) string {
	escapedPkg := shellEscapeSingleQuotes(pkg)
	return fmt.Sprintf(
		"sh -c \"apt-get changelog '%s' 2>/dev/null | grep -Eo 'CVE-[0-9]{4}-[0-9]+' | sort -u | head -n %d\"",
		escapedPkg,
		cveLookupMaxPerPackage,
	)
}

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting: %s", message)
}

func TestParseUpgradableEntriesStructured(t *testing.T) {
	stdout := "Inst openssl [3.0.0-1] (3.0.1-1 Debian-Security:12/stable-security [amd64])\n" +
		"Inst bash [5.2-1] (5.2-2 Debian:12 [amd64])\n"

	pending, raw, err := parseUpgradableEntries(stdout)
	if err != nil {
		t.Fatalf("parseUpgradableEntries() error = %v", err)
	}
	if len(raw) != 2 || len(pending) != 2 {
		t.Fatalf("len(raw)=%d len(pending)=%d, want 2/2", len(raw), len(pending))
	}

	if pending[0].Package != "openssl" || pending[0].CurrentVersion != "3.0.0-1" || pending[0].CandidateVersion != "3.0.1-1" {
		t.Fatalf("unexpected first parsed package: %+v", pending[0])
	}
	if !pending[0].Security {
		t.Fatalf("expected openssl update to be security: %+v", pending[0])
	}
	if pending[1].Package != "bash" || pending[1].Security {
		t.Fatalf("unexpected second parsed package: %+v", pending[1])
	}
}

func TestBuildSelectedUpgradeCmd(t *testing.T) {
	got := buildSelectedUpgradeCmd([]string{"openssl", "python3.11", "libfoo'bar"})
	want := "sudo apt-get -y install --only-upgrade -- 'openssl' 'python3.11' 'libfoo'\"'\"'bar'"
	if got != want {
		t.Fatalf("buildSelectedUpgradeCmd() = %q, want %q", got, want)
	}

	if empty := buildSelectedUpgradeCmd(nil); empty != "" {
		t.Fatalf("buildSelectedUpgradeCmd(nil) = %q, want empty", empty)
	}
}

func TestApprovePendingUpdateScope(t *testing.T) {
	preserveServerState(t)

	mu.Lock()
	statusMap = map[string]*ServerStatus{
		"srv": {
			Name:   "srv",
			Status: "pending_approval",
		},
	}
	mu.Unlock()

	exists, approved := approvePendingUpdate("srv", "security")
	if !exists || !approved {
		t.Fatalf("approvePendingUpdate(srv, security) = exists=%t approved=%t, want true/true", exists, approved)
	}

	mu.Lock()
	gotStatus := statusMap["srv"].Status
	gotScope := statusMap["srv"].ApprovalScope
	mu.Unlock()
	if gotStatus != "approved" {
		t.Fatalf("status after approve = %q, want approved", gotStatus)
	}
	if gotScope != "security" {
		t.Fatalf("approval scope after approve = %q, want security", gotScope)
	}

	mu.Lock()
	statusMap["srv"].Status = "idle"
	mu.Unlock()
	exists, approved = approvePendingUpdate("srv", "all")
	if !exists || approved {
		t.Fatalf("approvePendingUpdate(srv, all) when idle = exists=%t approved=%t, want true/false", exists, approved)
	}
}

func TestSortPendingUpdatesSecurityFirstThenCVECount(t *testing.T) {
	updates := []PendingUpdate{
		{Package: "pkg-b", Security: false, CVEs: []string{"CVE-2026-0003"}},
		{Package: "pkg-a", Security: true, CVEs: []string{}},
		{Package: "pkg-c", Security: true, CVEs: []string{"CVE-2026-0001", "CVE-2026-0002"}},
	}
	sortPendingUpdates(updates)
	gotOrder := []string{updates[0].Package, updates[1].Package, updates[2].Package}
	wantOrder := []string{"pkg-c", "pkg-a", "pkg-b"}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Fatalf("order[%d] = %q, want %q (all=%v)", i, gotOrder[i], wantOrder[i], gotOrder)
		}
	}
}

func TestExtractCVEsFromTextDedupAndMax(t *testing.T) {
	text := "CVE-2026-0002\nnoise\ncve-2026-0001\nCVE-2026-0002\nCVE-2026-0003\n"
	got := extractCVEsFromText(text, 2)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%v)", len(got), got)
	}
	if got[0] != "CVE-2026-0001" || got[1] != "CVE-2026-0002" {
		t.Fatalf("unexpected CVEs: %v", got)
	}
}

func TestCloneStatusMapDeepCopiesPendingUpdates(t *testing.T) {
	src := map[string]*ServerStatus{
		"srv": {
			Name: "srv",
			PendingUpdates: []PendingUpdate{{
				Package:  "openssl",
				CVEs:     []string{"CVE-2026-0001"},
				CVEState: "ready",
			}},
		},
	}
	cloned := cloneStatusMap(src)
	src["srv"].PendingUpdates[0].CVEs[0] = "CVE-CHANGED"

	got := cloned["srv"].PendingUpdates[0].CVEs[0]
	if got != "CVE-2026-0001" {
		t.Fatalf("cloned CVE mutated = %q, want original", got)
	}
}

func TestRunUpdateWithActorCVEEnrichmentReadyAndClearedOnCancel(t *testing.T) {
	preserveServerState(t)
	preserveDBState(t)

	t.Setenv(retryMaxAttemptsEnv, "1")
	dbFile := filepath.Join(t.TempDir(), "cve-ready.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)

	server := Server{Name: "srv-cve-ready", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	updateConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "2048000\n2097152\n"},
			precheckLocksCmd:     {err: fakeExitStatusError{code: 1, msg: "no process found"}},
			precheckDpkgAuditCmd: {},
			precheckAptCheckCmd:  {},
			aptUpdateCmd:         {},
			aptListUpgradableCmd: {stdout: "Inst openssl [3.0.0-1] (3.0.1-1 Debian-Security:12/stable-security [amd64])\nInst bash [5.2-1] (5.2-2 Debian:12 [amd64])\n"},
		},
	}
	cveConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			changelogCVECommand("openssl"): {stdout: "CVE-2026-1002\nCVE-2026-1001\n"},
			changelogCVECommand("bash"):    {},
		},
	}

	origDial := dialSSHConnection
	dialCalls := 0
	dialSSHConnection = func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		dialCalls++
		if dialCalls == 1 {
			return updateConn, nil
		}
		return cveConn, nil
	}
	t.Cleanup(func() { dialSSHConnection = origDial })

	done := make(chan struct{})
	go func() {
		runUpdateWithActor(server, "tester", "127.0.0.1", loadRetryPolicyFromEnv())
		close(done)
	}()

	waitForCondition(t, 6*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		status := statusMap[server.Name]
		if status == nil || status.Status != "pending_approval" || len(status.PendingUpdates) < 2 {
			return false
		}
		for _, update := range status.PendingUpdates {
			if update.Package == "openssl" && update.CVEState == "ready" && len(update.CVEs) >= 2 {
				return true
			}
		}
		return false
	}, "pending approval with enriched CVE data")

	mu.Lock()
	pending := clonePendingUpdates(statusMap[server.Name].PendingUpdates)
	statusMap[server.Name].Status = "cancelled"
	mu.Unlock()

	if len(pending) < 2 || pending[0].Package != "openssl" || !pending[0].Security {
		t.Fatalf("pending updates not sorted security-first: %+v", pending)
	}

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for update flow to exit")
	}

	mu.Lock()
	final := statusMap[server.Name]
	mu.Unlock()
	if final.Status != "idle" {
		t.Fatalf("final status = %q, want idle", final.Status)
	}
	if len(final.PendingUpdates) != 0 {
		t.Fatalf("PendingUpdates not cleared: %+v", final.PendingUpdates)
	}
	if len(final.Upgradable) != 0 {
		t.Fatalf("Upgradable not cleared: %+v", final.Upgradable)
	}
}

func TestRunUpdateWithActorCVEEnrichmentUnavailable(t *testing.T) {
	preserveServerState(t)
	preserveDBState(t)

	t.Setenv(retryMaxAttemptsEnv, "1")
	dbFile := filepath.Join(t.TempDir(), "cve-unavailable.db")
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)

	server := Server{Name: "srv-cve-unavailable", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()

	updateConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "2048000\n2097152\n"},
			precheckLocksCmd:     {err: fakeExitStatusError{code: 1, msg: "no process found"}},
			precheckDpkgAuditCmd: {},
			precheckAptCheckCmd:  {},
			aptUpdateCmd:         {},
			aptListUpgradableCmd: {stdout: "Inst openssl [3.0.0-1] (3.0.1-1 Debian-Security:12/stable-security [amd64])\n"},
		},
	}
	cveConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			changelogCVECommand("openssl"): {err: errors.New("lookup failed")},
		},
	}

	origDial := dialSSHConnection
	dialCalls := 0
	dialSSHConnection = func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		dialCalls++
		if dialCalls == 1 {
			return updateConn, nil
		}
		return cveConn, nil
	}
	t.Cleanup(func() { dialSSHConnection = origDial })

	done := make(chan struct{})
	go func() {
		runUpdateWithActor(server, "tester", "127.0.0.1", loadRetryPolicyFromEnv())
		close(done)
	}()

	waitForCondition(t, 6*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		status := statusMap[server.Name]
		if status == nil || status.Status != "pending_approval" || len(status.PendingUpdates) != 1 {
			return false
		}
		return status.PendingUpdates[0].CVEState == "unavailable"
	}, "pending approval with unavailable CVE lookup")

	mu.Lock()
	statusMap[server.Name].Status = "cancelled"
	mu.Unlock()

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for update flow to exit")
	}
}
