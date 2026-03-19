package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func setupAuthenticatedHandler(t *testing.T, dbFile string) (http.Handler, *http.Cookie) {
	t.Helper()
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)

	r, err := setupRouter()
	if err != nil {
		t.Fatalf("setupRouter() unexpected error: %v", err)
	}
	handler := sessionManager.LoadAndSave(r)

	setupBody := bytes.NewBufferString(`{"username":"admin","password":"` + testPasswordStrong + `"}`)
	setupRec := httptest.NewRecorder()
	setupReq := httptest.NewRequest(http.MethodPost, "/api/auth/setup", setupBody)
	markSameOriginAuthRequest(setupReq)
	setupReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want %d (body=%s)", setupRec.Code, http.StatusOK, setupRec.Body.String())
	}
	return handler, testSessionCookieFromRecorder(t, setupRec)
}

func TestUpdateRouteStartsFromIdleAndConflictsWhenBusy(t *testing.T) {
	t.Run("starts from idle", func(t *testing.T) {
		preserveDBState(t)
		preserveServerState(t)
		preserveSessionState(t)
		preserveRateLimiterState(t)
		preserveMetricsTokenState(t)
		dbFile := filepath.Join(t.TempDir(), "actions-start-update.db")
		knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
			t.Fatalf("write known_hosts: %v", err)
		}
		t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)
		handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

		server := Server{Name: "srv-update-route", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
		func() {
			mu.Lock()
			defer mu.Unlock()
			servers = []Server{server}
			statusMap = map[string]*ServerStatus{
				server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
			}
		}()

		origDial := getDialSSHConnection()
		setDialSSHConnection(func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
			return &slowSSHConnection{delay: 3 * time.Second}, nil
		})
		t.Cleanup(func() { setDialSSHConnection(origDial) })
		t.Setenv(sshCommandTimeoutSecondsEnv, "1")
		t.Setenv(retryMaxAttemptsEnv, "1")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/update/"+server.Name, nil)
		req.AddCookie(sessionCookie)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("update start status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
		}

		waitForCondition(t, 3*time.Second, func() bool {
			mu.Lock()
			defer mu.Unlock()
			status := statusMap[server.Name]
			return status != nil && status.Status != "idle"
		}, "server leaves idle state after update start")

		waitForCondition(t, 8*time.Second, func() bool {
			mu.Lock()
			defer mu.Unlock()
			status := statusMap[server.Name]
			if status == nil {
				return false
			}
			switch status.Status {
			case "done", "error", "approved", "cancelled", "idle":
				return true
			default:
				return false
			}
		}, "server returns to terminal state after update start")
	})

	t.Run("returns conflict when busy", func(t *testing.T) {
		preserveDBState(t)
		preserveServerState(t)
		preserveSessionState(t)
		preserveRateLimiterState(t)
		preserveMetricsTokenState(t)
		dbFile := filepath.Join(t.TempDir(), "actions-update-conflict.db")
		handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

		server := Server{Name: "srv-update-conflict", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
		func() {
			mu.Lock()
			defer mu.Unlock()
			servers = []Server{server}
			statusMap = map[string]*ServerStatus{
				server.Name: {Name: server.Name, Status: "updating", Upgradable: []string{}},
			}
		}()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/update/"+server.Name, nil)
		req.AddCookie(sessionCookie)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("update start conflict status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
		}
	})
}

func TestApproveCancelRoutesRespectPendingState(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	dbFile := filepath.Join(t.TempDir(), "actions-approve-cancel.db")
	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	server := Server{Name: "srv-approval-route", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	pending := []PendingUpdate{{Package: "openssl", Security: true}}

	func() {
		mu.Lock()
		defer mu.Unlock()
		servers = []Server{server}
		statusMap = map[string]*ServerStatus{
			server.Name: {
				Name:           server.Name,
				Status:         "pending_approval",
				Upgradable:     []string{"openssl"},
				PendingUpdates: clonePendingUpdates(pending),
				Logs:           "pending",
			},
		}
	}()

	approveRec := httptest.NewRecorder()
	approveReq := httptest.NewRequest(http.MethodPost, "/api/approve/"+server.Name, nil)
	approveReq.AddCookie(sessionCookie)
	handler.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want %d (body=%s)", approveRec.Code, http.StatusOK, approveRec.Body.String())
	}
	var approvedStatus *ServerStatus
	func() {
		mu.Lock()
		defer mu.Unlock()
		approvedStatus = statusMap[server.Name]
	}()
	if approvedStatus == nil || approvedStatus.Status != "approved" {
		t.Fatalf("status after approve = %+v, want approved", approvedStatus)
	}

	approveAgainRec := httptest.NewRecorder()
	approveAgainReq := httptest.NewRequest(http.MethodPost, "/api/approve/"+server.Name, nil)
	approveAgainReq.AddCookie(sessionCookie)
	handler.ServeHTTP(approveAgainRec, approveAgainReq)
	if approveAgainRec.Code != http.StatusConflict {
		t.Fatalf("approve conflict status = %d, want %d (body=%s)", approveAgainRec.Code, http.StatusConflict, approveAgainRec.Body.String())
	}

	func() {
		mu.Lock()
		defer mu.Unlock()
		status, ok := statusMap[server.Name]
		if !ok || status == nil {
			t.Fatalf("statusMap[%q] missing before pending reset", server.Name)
		}
		status.Status = "pending_approval"
		status.ApprovalScope = ""
		status.Upgradable = []string{"openssl"}
		status.PendingUpdates = clonePendingUpdates(pending)
		status.Logs = "pending"
	}()

	cancelRec := httptest.NewRecorder()
	cancelReq := httptest.NewRequest(http.MethodPost, "/api/cancel/"+server.Name, nil)
	cancelReq.AddCookie(sessionCookie)
	handler.ServeHTTP(cancelRec, cancelReq)
	if cancelRec.Code != http.StatusOK {
		t.Fatalf("cancel status = %d, want %d (body=%s)", cancelRec.Code, http.StatusOK, cancelRec.Body.String())
	}
	var cancelledStatus *ServerStatus
	func() {
		mu.Lock()
		defer mu.Unlock()
		cancelledStatus = statusMap[server.Name]
	}()
	if cancelledStatus == nil || cancelledStatus.Status != "cancelled" {
		t.Fatalf("status after cancel = %+v, want cancelled", cancelledStatus)
	}
	if len(cancelledStatus.Upgradable) != 0 || len(cancelledStatus.PendingUpdates) != 0 || cancelledStatus.Logs != "" {
		t.Fatalf("cancel should clear pending state, got %+v", cancelledStatus)
	}

	cancelAgainRec := httptest.NewRecorder()
	cancelAgainReq := httptest.NewRequest(http.MethodPost, "/api/cancel/"+server.Name, nil)
	cancelAgainReq.AddCookie(sessionCookie)
	handler.ServeHTTP(cancelAgainRec, cancelAgainReq)
	if cancelAgainRec.Code != http.StatusConflict {
		t.Fatalf("cancel conflict status = %d, want %d (body=%s)", cancelAgainRec.Code, http.StatusConflict, cancelAgainRec.Body.String())
	}
}

func TestBulkUpdateRouteHandlesConcurrentStarts(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)

	dbFile := filepath.Join(t.TempDir(), "actions-bulk-update-concurrent.db")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)
	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	serverCount := 16
	localServers := make([]Server, 0, serverCount)
	localStatus := make(map[string]*ServerStatus, serverCount)
	for i := 0; i < serverCount; i++ {
		name := fmt.Sprintf("srv-bulk-%02d", i)
		s := Server{Name: name, Host: "example.org", Port: 22, User: "root", Pass: "pw"}
		localServers = append(localServers, s)
		localStatus[name] = &ServerStatus{Name: name, Status: "idle", Upgradable: []string{}}
	}
	func() {
		mu.Lock()
		defer mu.Unlock()
		servers = localServers
		statusMap = localStatus
	}()

	origDial := getDialSSHConnection()
	setDialSSHConnection(func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		return &slowSSHConnection{delay: 2 * time.Second}, nil
	})
	t.Cleanup(func() { setDialSSHConnection(origDial) })
	t.Setenv(sshCommandTimeoutSecondsEnv, "1")
	t.Setenv(retryMaxAttemptsEnv, "1")

	var wg sync.WaitGroup
	type result struct {
		name string
		code int
		body string
	}
	resultsCh := make(chan result, serverCount)
	for _, s := range localServers {
		wg.Add(1)
		go func(serverName string) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/update/"+serverName, nil)
			req.AddCookie(sessionCookie)
			handler.ServeHTTP(rec, req)
			resultsCh <- result{name: serverName, code: rec.Code, body: rec.Body.String()}
		}(s.Name)
	}
	wg.Wait()
	close(resultsCh)

	for res := range resultsCh {
		if res.code != http.StatusOK {
			t.Fatalf("bulk update start for %s status = %d, want %d (body=%s)", res.name, res.code, http.StatusOK, res.body)
		}
	}
}
