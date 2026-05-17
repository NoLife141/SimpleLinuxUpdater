package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkdownReportEndpoints(t *testing.T) {
	preserveDBState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	dbFile := filepath.Join(t.TempDir(), "reports.db")
	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	if err := writeAuditEvent(AuditEvent{
		CreatedAt:  "2026-05-17T12:00:00Z",
		Actor:      "admin",
		Action:     updateCompleteAction,
		TargetType: "server",
		TargetName: "srv-report",
		Status:     "success",
		Message:    "Final status: done",
		MetaJSON:   `{"execution_duration_ms":1234}`,
	}); err != nil {
		t.Fatalf("writeAuditEvent() error = %v", err)
	}
	var auditID int64
	if err := getDB().QueryRow("SELECT id FROM audit_events WHERE action = ? ORDER BY id DESC LIMIT 1", updateCompleteAction).Scan(&auditID); err != nil {
		t.Fatalf("load audit id: %v", err)
	}

	auditReq := httptest.NewRequest(http.MethodGet, "/api/reports/audit/"+strconvFormatInt(auditID), nil)
	auditReq.AddCookie(sessionCookie)
	auditRec := httptest.NewRecorder()
	handler.ServeHTTP(auditRec, auditReq)
	if auditRec.Code != http.StatusOK {
		t.Fatalf("audit report status = %d, want %d (body=%s)", auditRec.Code, http.StatusOK, auditRec.Body.String())
	}
	if !strings.Contains(auditRec.Body.String(), "# Audit Event Report #"+strconvFormatInt(auditID)) || !strings.Contains(auditRec.Body.String(), "execution_duration_ms") {
		t.Fatalf("audit report body missing expected content:\n%s", auditRec.Body.String())
	}

	job, err := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: "srv-report",
		Actor:      "admin",
		Status:     jobStatusSucceeded,
		Summary:    "Update completed",
		LogsText:   "Upgrade completed.",
	})
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	jobReq := httptest.NewRequest(http.MethodGet, "/api/reports/jobs/"+job.ID, nil)
	jobReq.AddCookie(sessionCookie)
	jobRec := httptest.NewRecorder()
	handler.ServeHTTP(jobRec, jobReq)
	if jobRec.Code != http.StatusOK {
		t.Fatalf("job report status = %d, want %d (body=%s)", jobRec.Code, http.StatusOK, jobRec.Body.String())
	}
	if !strings.Contains(jobRec.Body.String(), "# Update Job Report "+job.ID) || !strings.Contains(jobRec.Body.String(), "Upgrade completed.") {
		t.Fatalf("job report body missing expected content:\n%s", jobRec.Body.String())
	}
}
