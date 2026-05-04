package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
		t.Cleanup(func() {
			waitForUpdateRunners()
			setDialSSHConnection(origDial)
		})
		t.Setenv(sshCommandTimeoutSecondsEnv, "1")
		t.Setenv(retryMaxAttemptsEnv, "1")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/update/"+server.Name, nil)
		req.AddCookie(sessionCookie)
		markSameOriginAuthRequest(req)
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
		markSameOriginAuthRequest(req)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("update start conflict status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
		}
	})
}

func TestServerMutationRoutesRejectActiveServerActions(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	dbFile := filepath.Join(t.TempDir(), "server-mutation-active.db")
	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	server := Server{Name: "srv-active-mutation", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	func() {
		mu.Lock()
		defer mu.Unlock()
		servers = []Server{server}
		statusMap = map[string]*ServerStatus{
			server.Name: {Name: server.Name, Status: "updating", Upgradable: []string{}},
		}
	}()
	if err := saveServers(); err != nil {
		t.Fatalf("saveServers() unexpected error: %v", err)
	}

	updateBody := bytes.NewBufferString(`{"name":"srv-active-renamed","host":"example.net","port":22,"user":"root"}`)
	updateRec := httptest.NewRecorder()
	updateReq := httptest.NewRequest(http.MethodPut, "/api/servers/"+server.Name, updateBody)
	updateReq.AddCookie(sessionCookie)
	updateReq.Header.Set("Content-Type", "application/json")
	markSameOriginAuthRequest(updateReq)
	handler.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusConflict {
		t.Fatalf("active server update status = %d, want %d (body=%s)", updateRec.Code, http.StatusConflict, updateRec.Body.String())
	}

	deleteRec := httptest.NewRecorder()
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/servers/"+server.Name, nil)
	deleteReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(deleteReq)
	handler.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusConflict {
		t.Fatalf("active server delete status = %d, want %d (body=%s)", deleteRec.Code, http.StatusConflict, deleteRec.Body.String())
	}

	passwordRec := httptest.NewRecorder()
	passwordReq := httptest.NewRequest(http.MethodDelete, "/api/servers/"+server.Name+"/password", nil)
	passwordReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(passwordReq)
	handler.ServeHTTP(passwordRec, passwordReq)
	if passwordRec.Code != http.StatusConflict {
		t.Fatalf("active server password clear status = %d, want %d (body=%s)", passwordRec.Code, http.StatusConflict, passwordRec.Body.String())
	}

	var keyBody bytes.Buffer
	keyWriter := multipart.NewWriter(&keyBody)
	keyPart, err := keyWriter.CreateFormFile("key", "id_ed25519")
	if err != nil {
		t.Fatalf("CreateFormFile() unexpected error: %v", err)
	}
	if _, err := keyPart.Write([]byte("private-key")); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	if err := keyWriter.Close(); err != nil {
		t.Fatalf("multipart close unexpected error: %v", err)
	}
	keyUploadRec := httptest.NewRecorder()
	keyUploadReq := httptest.NewRequest(http.MethodPost, "/api/servers/"+server.Name+"/key", &keyBody)
	keyUploadReq.AddCookie(sessionCookie)
	keyUploadReq.Header.Set("Content-Type", keyWriter.FormDataContentType())
	markSameOriginAuthRequest(keyUploadReq)
	handler.ServeHTTP(keyUploadRec, keyUploadReq)
	if keyUploadRec.Code != http.StatusConflict {
		t.Fatalf("active server key upload status = %d, want %d (body=%s)", keyUploadRec.Code, http.StatusConflict, keyUploadRec.Body.String())
	}

	keyClearRec := httptest.NewRecorder()
	keyClearReq := httptest.NewRequest(http.MethodDelete, "/api/servers/"+server.Name+"/key", nil)
	keyClearReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(keyClearReq)
	handler.ServeHTTP(keyClearRec, keyClearReq)
	if keyClearRec.Code != http.StatusConflict {
		t.Fatalf("active server key clear status = %d, want %d (body=%s)", keyClearRec.Code, http.StatusConflict, keyClearRec.Body.String())
	}

	factsRec := httptest.NewRecorder()
	factsReq := httptest.NewRequest(http.MethodPost, "/api/servers/"+server.Name+"/facts/refresh", nil)
	factsReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(factsReq)
	handler.ServeHTTP(factsRec, factsReq)
	if factsRec.Code != http.StatusConflict {
		t.Fatalf("active server facts refresh status = %d, want %d (body=%s)", factsRec.Code, http.StatusConflict, factsRec.Body.String())
	}

	globalKeyUploadRec := httptest.NewRecorder()
	globalKeyUploadReq := httptest.NewRequest(http.MethodPost, "/api/keys/global", nil)
	globalKeyUploadReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(globalKeyUploadReq)
	handler.ServeHTTP(globalKeyUploadRec, globalKeyUploadReq)
	if globalKeyUploadRec.Code != http.StatusConflict {
		t.Fatalf("active server global key upload status = %d, want %d (body=%s)", globalKeyUploadRec.Code, http.StatusConflict, globalKeyUploadRec.Body.String())
	}

	globalKeyClearRec := httptest.NewRecorder()
	globalKeyClearReq := httptest.NewRequest(http.MethodDelete, "/api/keys/global", nil)
	globalKeyClearReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(globalKeyClearReq)
	handler.ServeHTTP(globalKeyClearRec, globalKeyClearReq)
	if globalKeyClearRec.Code != http.StatusConflict {
		t.Fatalf("active server global key clear status = %d, want %d (body=%s)", globalKeyClearRec.Code, http.StatusConflict, globalKeyClearRec.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(servers) != 1 || servers[0].Name != server.Name {
		t.Fatalf("active server was mutated: %+v", servers)
	}
	if status := statusMap[server.Name]; status == nil || status.Status != "updating" {
		t.Fatalf("active server status changed: %+v", status)
	}
}

func TestFactsRefreshBlocksConcurrentServerActions(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	dbFile := filepath.Join(t.TempDir(), "facts-refresh-busy.db")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)
	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	server := Server{Name: "srv-facts-busy", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	func() {
		mu.Lock()
		defer mu.Unlock()
		servers = []Server{server}
		statusMap = map[string]*ServerStatus{
			server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
		}
	}()

	enteredDial := make(chan struct{})
	releaseDial := make(chan struct{})
	origDial := getDialSSHConnection()
	setDialSSHConnection(func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		close(enteredDial)
		<-releaseDial
		return &scriptedSSHConnection{
			responses: map[string]scriptedResponse{
				serverFactsOSCmd:           {stdout: "Ubuntu 24.04 LTS\n"},
				serverFactsUptimeCmd:       {stdout: "12345.67 100.00\n"},
				precheckDiskSpaceCmd:       {stdout: "2097152\n3145728\n"},
				precheckDpkgAuditCmd:       {},
				precheckAptCheckCmd:        {},
				postcheckRebootRequiredCmd: {},
			},
		}, nil
	})
	t.Cleanup(func() {
		setDialSSHConnection(origDial)
	})

	factsDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/servers/"+server.Name+"/facts/refresh", nil)
		req.AddCookie(sessionCookie)
		markSameOriginAuthRequest(req)
		handler.ServeHTTP(rec, req)
		factsDone <- rec.Code
	}()

	select {
	case <-enteredDial:
	case <-time.After(2 * time.Second):
		t.Fatalf("facts refresh did not enter SSH dial")
	}

	updateRec := httptest.NewRecorder()
	updateReq := httptest.NewRequest(http.MethodPost, "/api/update/"+server.Name, nil)
	updateReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(updateReq)
	handler.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusConflict {
		t.Fatalf("update during facts refresh status = %d, want %d (body=%s)", updateRec.Code, http.StatusConflict, updateRec.Body.String())
	}

	close(releaseDial)
	select {
	case code := <-factsDone:
		if code != http.StatusOK {
			t.Fatalf("facts refresh status = %d, want %d", code, http.StatusOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("facts refresh did not finish")
	}
}

func TestStartJobRunnerMarksPanicFailedWithoutCrashing(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "job-panic.db"))
	if err := initializeJobManager(); err != nil {
		t.Fatalf("initializeJobManager() unexpected error: %v", err)
	}
	job, err := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: "srv-panic",
		Actor:      "tester",
		ClientIP:   "127.0.0.1",
		Status:     jobStatusQueued,
	})
	if err != nil {
		t.Fatalf("CreateJob() unexpected error: %v", err)
	}

	startJobRunner(job.ID, func() {
		panic("boom")
	})

	waitForCondition(t, 2*time.Second, func() bool {
		record, err := currentJobManager().GetJob(job.ID)
		return err == nil && record.Status == jobStatusFailed && record.Phase == jobPhaseComplete && record.ErrorClass == "panic"
	}, "panicked job is marked failed without crashing")
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
	_, createErr := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: server.Name,
		Actor:      "tester",
		ClientIP:   "127.0.0.1",
		Status:     jobStatusWaitingApproval,
		Phase:      jobPhaseApprovalWait,
		Summary:    "Waiting for approval",
	})
	if createErr != nil {
		t.Fatalf("CreateJob(update pending approval) unexpected error: %v", createErr)
	}

	approveRec := httptest.NewRecorder()
	approveReq := httptest.NewRequest(http.MethodPost, "/api/approve/"+server.Name, nil)
	approveReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(approveReq)
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
	markSameOriginAuthRequest(approveAgainReq)
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
	_, createErr = currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: server.Name,
		Actor:      "tester",
		ClientIP:   "127.0.0.1",
		Status:     jobStatusWaitingApproval,
		Phase:      jobPhaseApprovalWait,
		Summary:    "Waiting for approval",
	})
	if createErr != nil {
		t.Fatalf("CreateJob(update pending approval) unexpected error: %v", createErr)
	}

	cancelRec := httptest.NewRecorder()
	cancelReq := httptest.NewRequest(http.MethodPost, "/api/cancel/"+server.Name, nil)
	cancelReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(cancelReq)
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
	markSameOriginAuthRequest(cancelAgainReq)
	handler.ServeHTTP(cancelAgainRec, cancelAgainReq)
	if cancelAgainRec.Code != http.StatusConflict {
		t.Fatalf("cancel conflict status = %d, want %d (body=%s)", cancelAgainRec.Code, http.StatusConflict, cancelAgainRec.Body.String())
	}
}

func TestCancelRouteReturnsFailureWhenPendingJobCannotBePersisted(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)

	dbFile := filepath.Join(t.TempDir(), "actions-cancel-persist-failure.db")
	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	server := Server{Name: "srv-cancel-persist-failure", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	pending := []PendingUpdate{{Package: "openssl", Security: true, Raw: "Inst openssl"}}
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

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cancel/"+server.Name, nil)
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("cancel status = %d, want %d (body=%s)", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}

	runtimeStatus := currentStatusSnapshot(server.Name)
	if runtimeStatus == nil {
		t.Fatalf("status snapshot missing after failed cancel")
	}
	if runtimeStatus.Status != "pending_approval" || runtimeStatus.Logs != "pending" {
		t.Fatalf("runtime status after failed cancel = %+v, want restored pending state", runtimeStatus)
	}
	if len(runtimeStatus.Upgradable) != 1 || len(runtimeStatus.PendingUpdates) != 1 {
		t.Fatalf("runtime status after failed cancel should keep pending data, got %+v", runtimeStatus)
	}
}

func TestApproveRouteUpdatesJobWithoutOverwritingApprovedRuntimeState(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)

	dbFile := filepath.Join(t.TempDir(), "actions-approve-job-sync.db")
	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	server := Server{Name: "srv-approval-job-sync", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	pending := []PendingUpdate{{Package: "openssl", Security: true, Raw: "Inst openssl"}}
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

	job, err := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: server.Name,
		Actor:      "tester",
		ClientIP:   "127.0.0.1",
		Status:     jobStatusWaitingApproval,
		Phase:      jobPhaseApprovalWait,
		Summary:    "Waiting for approval",
	})
	if err != nil {
		t.Fatalf("CreateJob(update pending approval) unexpected error: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/approve/"+server.Name, nil)
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	func() {
		mu.Lock()
		defer mu.Unlock()
		status := statusMap[server.Name]
		if status == nil || status.Status != "approved" {
			t.Fatalf("status after approve = %+v, want approved", status)
		}
	}()

	var approvedJobStatus, approvedJobPhase string
	if err := getDB().QueryRow("SELECT status, phase FROM jobs WHERE id = ?", job.ID).Scan(&approvedJobStatus, &approvedJobPhase); err != nil {
		t.Fatalf("query approved job: %v", err)
	}
	if approvedJobStatus != jobStatusRunning || approvedJobPhase != jobPhaseAptUpgrade {
		t.Fatalf("approved job status/phase = %q/%q, want %q/%q", approvedJobStatus, approvedJobPhase, jobStatusRunning, jobPhaseAptUpgrade)
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
	t.Cleanup(func() {
		waitForUpdateRunners()
		setDialSSHConnection(origDial)
	})
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
			markSameOriginAuthRequest(req)
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

func TestAsyncActionRoutesReturnJobIDAndPersistJobRecords(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		kind       string
		statusName string
	}{
		{name: "update", path: "/api/update/%s", body: "", kind: jobKindUpdate, statusName: "updating"},
		{name: "autoremove", path: "/api/autoremove/%s", body: "", kind: jobKindAutoremove, statusName: "autoremove"},
		{name: "sudoers enable", path: "/api/sudoers/%s", body: `{"password":"pw"}`, kind: jobKindSudoersEnable, statusName: "sudoers"},
		{name: "sudoers disable", path: "/api/sudoers/disable/%s", body: `{"password":"pw"}`, kind: jobKindSudoersDisable, statusName: "sudoers"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			preserveDBState(t)
			preserveServerState(t)
			preserveSessionState(t)
			preserveRateLimiterState(t)
			preserveMetricsTokenState(t)
			dbFile := filepath.Join(t.TempDir(), strings.ReplaceAll(tc.kind, "/", "-")+".db")
			handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

			server := Server{Name: "srv-" + strings.ReplaceAll(tc.kind, "_", "-"), Host: "example.org", Port: 22, User: "root", Pass: "pw"}
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
				return &slowSSHConnection{delay: 50 * time.Millisecond}, nil
			})
			t.Cleanup(func() {
				waitForUpdateRunners()
				setDialSSHConnection(origDial)
			})
			t.Setenv(retryMaxAttemptsEnv, "1")
			t.Setenv(sshCommandTimeoutSecondsEnv, "1")

			var body *bytes.Buffer
			if tc.body == "" {
				body = bytes.NewBuffer(nil)
			} else {
				body = bytes.NewBufferString(tc.body)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf(tc.path, server.Name), body)
			req.AddCookie(sessionCookie)
			markSameOriginAuthRequest(req)
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want %d (body=%s)", tc.name, rec.Code, http.StatusOK, rec.Body.String())
			}

			var payload struct {
				JobID string `json:"job_id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("unmarshal %s response: %v", tc.name, err)
			}
			if strings.TrimSpace(payload.JobID) == "" {
				t.Fatalf("%s response missing job_id: %s", tc.name, rec.Body.String())
			}

			var jobKind, jobStatus string
			if err := getDB().QueryRow("SELECT kind, status FROM jobs WHERE id = ?", payload.JobID).Scan(&jobKind, &jobStatus); err != nil {
				t.Fatalf("query %s job: %v", tc.name, err)
			}
			if jobKind != tc.kind {
				t.Fatalf("%s job kind = %q, want %q", tc.name, jobKind, tc.kind)
			}
			if strings.TrimSpace(jobStatus) == "" {
				t.Fatalf("%s job status should not be empty", tc.name)
			}
		})
	}
}

func TestActionRoutesRestoreRuntimeSnapshotWhenJobCreationFails(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		body    string
		wantErr string
	}{
		{name: "update", path: "/api/update/%s", wantErr: "Failed to create update job"},
		{name: "autoremove", path: "/api/autoremove/%s", wantErr: "Failed to create autoremove job"},
		{name: "sudoers enable", path: "/api/sudoers/%s", body: `{"password":"pw"}`, wantErr: "Failed to create sudoers job"},
		{name: "sudoers disable", path: "/api/sudoers/disable/%s", body: `{"password":"pw"}`, wantErr: "Failed to create sudoers disable job"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			preserveDBState(t)
			preserveServerState(t)
			preserveSessionState(t)
			preserveRateLimiterState(t)
			preserveMetricsTokenState(t)

			dbFile := filepath.Join(t.TempDir(), strings.ReplaceAll(tc.name, " ", "-")+".db")
			handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

			server := Server{Name: "srv-" + strings.ReplaceAll(tc.name, " ", "-"), Host: "example.org", Port: 22, User: "root", Pass: "pw"}
			original := &ServerStatus{
				Name:           server.Name,
				Host:           server.Host,
				Port:           server.Port,
				User:           server.User,
				Status:         "idle",
				Logs:           "",
				ApprovalScope:  "all",
				Upgradable:     []string{"held-package"},
				PendingUpdates: []PendingUpdate{{Package: "openssl", Raw: "Inst openssl"}},
				Tags:           []string{"prod"},
			}
			func() {
				mu.Lock()
				defer mu.Unlock()
				servers = []Server{server}
				statusMap = map[string]*ServerStatus{
					server.Name: {
						Name:           original.Name,
						Host:           original.Host,
						Port:           original.Port,
						User:           original.User,
						Status:         original.Status,
						Logs:           original.Logs,
						ApprovalScope:  original.ApprovalScope,
						Upgradable:     append([]string(nil), original.Upgradable...),
						PendingUpdates: clonePendingUpdates(original.PendingUpdates),
						Tags:           append([]string(nil), original.Tags...),
					},
				}
			}()

			setCurrentJobManager(nil)

			var body *bytes.Buffer
			if tc.body == "" {
				body = bytes.NewBuffer(nil)
			} else {
				body = bytes.NewBufferString(tc.body)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf(tc.path, server.Name), body)
			req.AddCookie(sessionCookie)
			markSameOriginAuthRequest(req)
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s status = %d, want %d (body=%s)", tc.name, rec.Code, http.StatusInternalServerError, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantErr) {
				t.Fatalf("%s body = %s, want error containing %q", tc.name, rec.Body.String(), tc.wantErr)
			}

			restored := currentStatusSnapshot(server.Name)
			if restored == nil {
				t.Fatalf("%s status snapshot missing after rollback", tc.name)
			}
			if !reflect.DeepEqual(restored, original) {
				t.Fatalf("%s restored status = %+v, want %+v", tc.name, restored, original)
			}
		})
	}
}

func TestCancelRoutePreservesExplicitCancelSummaryOnUpdateJob(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)

	dbFile := filepath.Join(t.TempDir(), "actions-cancel-summary.db")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)
	t.Setenv(retryMaxAttemptsEnv, "1")
	t.Setenv(postchecksEnabledEnv, "false")

	server := Server{Name: "srv-cancel-summary", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Upgradable: []string{}},
	}
	mu.Unlock()
	if err := initializeJobManager(); err != nil {
		t.Fatalf("initializeJobManager() unexpected error: %v", err)
	}
	job, err := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: server.Name,
		Actor:      "tester",
		ClientIP:   "127.0.0.1",
		Status:     jobStatusQueued,
	})
	if err != nil {
		t.Fatalf("CreateJob(update) unexpected error: %v", err)
	}

	origDial := getDialSSHConnection()
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
			buildPackageCVEQueryCmd("openssl"): {stdout: "CVE-2026-1002\n"},
		},
	}
	var dialCalls int32
	setDialSSHConnection(makeDialSSHValidator(server, &dialCalls, updateConn, cveConn))
	t.Cleanup(func() { setDialSSHConnection(origDial) })

	done := make(chan struct{})
	go func() {
		runUpdateJobWithActor(server, "tester", "127.0.0.1", loadRetryPolicyFromEnv(), job.ID)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		status := statusMap[server.Name]
		currentStatus := ""
		currentLogs := ""
		if status != nil {
			currentStatus = status.Status
			currentLogs = status.Logs
		}
		mu.Unlock()
		if currentStatus == "pending_approval" {
			break
		}
		time.Sleep(20 * time.Millisecond)
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for pending approval, last status=%q logs=%s", currentStatus, currentLogs)
		}
	}

	logsBeforeCancel := currentStatusLogs(server.Name)
	mu.Lock()
	status := statusMap[server.Name]
	status.Status = "cancelled"
	status.ApprovalScope = ""
	status.Logs = ""
	status.Upgradable = nil
	status.PendingUpdates = nil
	mu.Unlock()

	cancelledStatus := jobStatusCancelled
	cancelledPhase := jobPhaseComplete
	cancelledSummary := "Update cancelled"
	finishedAt := jobTimestampNow()
	if err := currentJobManager().UpdateJobWithoutRuntimeSync(job.ID, JobUpdate{
		Status:     &cancelledStatus,
		Phase:      &cancelledPhase,
		Summary:    &cancelledSummary,
		LogsText:   &logsBeforeCancel,
		FinishedAt: &finishedAt,
	}); err != nil {
		t.Fatalf("UpdateJobWithoutRuntimeSync(cancelled) unexpected error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for update flow to exit after cancellation")
	}

	var jobStatus, jobSummary string
	if err := getDB().QueryRow("SELECT status, summary FROM jobs WHERE id = ?", job.ID).Scan(&jobStatus, &jobSummary); err != nil {
		t.Fatalf("query cancelled job: %v", err)
	}
	if jobStatus != jobStatusCancelled {
		t.Fatalf("cancelled job status = %q, want %q", jobStatus, jobStatusCancelled)
	}
	if jobSummary != "Update cancelled" {
		t.Fatalf("cancelled job summary = %q, want %q", jobSummary, "Update cancelled")
	}
}

func TestCancelRouteDoesNotRehydrateClearedRuntimeLogsFromJobSync(t *testing.T) {
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)

	dbFile := filepath.Join(t.TempDir(), "actions-cancel-route-job-sync.db")
	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	server := Server{Name: "srv-cancel-route-job-sync", Host: "example.org", Port: 22, User: "root", Pass: "pw"}
	pending := []PendingUpdate{{Package: "openssl", Security: true, Raw: "Inst openssl"}}
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

	job, err := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: server.Name,
		Actor:      "tester",
		ClientIP:   "127.0.0.1",
		Status:     jobStatusWaitingApproval,
		Phase:      jobPhaseApprovalWait,
		Summary:    "Waiting for approval",
	})
	if err != nil {
		t.Fatalf("CreateJob(update pending approval) unexpected error: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cancel/"+server.Name, nil)
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	runtimeStatus := currentStatusSnapshot(server.Name)
	if runtimeStatus == nil {
		t.Fatalf("status snapshot missing after cancel")
	}
	if runtimeStatus.Status != "cancelled" {
		t.Fatalf("runtime status after cancel = %+v, want cancelled", runtimeStatus)
	}
	if runtimeStatus.Logs != "" || len(runtimeStatus.Upgradable) != 0 || len(runtimeStatus.PendingUpdates) != 0 {
		t.Fatalf("cancel route should keep cleared runtime state, got %+v", runtimeStatus)
	}

	var jobStatus, jobPhase, jobSummary, jobLogs string
	if err := getDB().QueryRow("SELECT status, phase, summary, logs_text FROM jobs WHERE id = ?", job.ID).Scan(&jobStatus, &jobPhase, &jobSummary, &jobLogs); err != nil {
		t.Fatalf("query cancelled job: %v", err)
	}
	if jobStatus != jobStatusCancelled || jobPhase != jobPhaseComplete {
		t.Fatalf("cancelled job status/phase = %q/%q, want %q/%q", jobStatus, jobPhase, jobStatusCancelled, jobPhaseComplete)
	}
	if jobSummary != "Update cancelled" {
		t.Fatalf("cancelled job summary = %q, want %q", jobSummary, "Update cancelled")
	}
	if jobLogs != "pending" {
		t.Fatalf("cancelled job logs_text = %q, want %q", jobLogs, "pending")
	}
}

func TestApproveRoutesReturnFailureWhenPendingJobCannotBePersisted(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantScope string
	}{
		{name: "approve all", path: "/api/approve/%s", wantScope: "all"},
		{name: "approve security", path: "/api/approve-security/%s", wantScope: "security"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			preserveDBState(t)
			preserveServerState(t)
			preserveSessionState(t)
			preserveRateLimiterState(t)
			preserveMetricsTokenState(t)

			dbFile := filepath.Join(t.TempDir(), strings.ReplaceAll(tc.name, " ", "-")+".db")
			handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

			server := Server{Name: "srv-" + strings.ReplaceAll(tc.name, " ", "-"), Host: "example.org", Port: 22, User: "root", Pass: "pw"}
			pending := []PendingUpdate{{Package: "openssl", Security: true, Raw: "Inst openssl"}}
			func() {
				mu.Lock()
				defer mu.Unlock()
				servers = []Server{server}
				statusMap = map[string]*ServerStatus{
					server.Name: {
						Name:           server.Name,
						Status:         "pending_approval",
						ApprovalScope:  "",
						Upgradable:     []string{"openssl"},
						PendingUpdates: clonePendingUpdates(pending),
						Logs:           "pending",
					},
				}
			}()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf(tc.path, server.Name), nil)
			req.AddCookie(sessionCookie)
			markSameOriginAuthRequest(req)
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s status = %d, want %d (body=%s)", tc.name, rec.Code, http.StatusInternalServerError, rec.Body.String())
			}

			runtimeStatus := currentStatusSnapshot(server.Name)
			if runtimeStatus == nil {
				t.Fatalf("%s runtime status missing after failed approval", tc.name)
			}
			if runtimeStatus.Status != "pending_approval" || runtimeStatus.ApprovalScope != "" || runtimeStatus.Logs != "pending" {
				t.Fatalf("%s runtime status after failed approval = %+v, want restored pending state", tc.name, runtimeStatus)
			}
			if len(runtimeStatus.Upgradable) != 1 || len(runtimeStatus.PendingUpdates) != 1 {
				t.Fatalf("%s runtime status after failed approval should keep pending data, got %+v", tc.name, runtimeStatus)
			}
		})
	}
}
