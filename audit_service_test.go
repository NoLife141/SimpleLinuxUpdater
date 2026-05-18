package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditServiceRecordSanitizesTruncatesAndNotifies(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "audit-service-record.db"))
	_ = getDB()

	var notifications []string
	svc := NewAuditService(getDB, func(reason string) {
		notifications = append(notifications, reason)
	}, fixedAuditTimezone)
	svc.now = func() time.Time {
		return time.Date(2026, 5, 17, 12, 34, 56, 0, time.UTC)
	}

	longAction := strings.Repeat("a", 80)
	longStatus := strings.Repeat("s", 40)
	longClientIP := strings.Repeat("1", 150)
	longMessage := strings.Repeat("m", auditMessageMaxLen+20)
	meta := map[string]any{
		"safe":     strings.Repeat("x", auditMetaMaxLen*2),
		"password": "should-not-be-stored",
	}

	if err := svc.Record("", longClientIP, longAction, "server", "", longStatus, longMessage, meta); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(notifications) != 1 || notifications[0] != longAction {
		t.Fatalf("notifications = %v, want raw action once", notifications)
	}

	var evt AuditEvent
	if err := getDB().QueryRow(`
		SELECT created_at, actor, action, target_type, target_name, status, message, meta_json, client_ip
		  FROM audit_events
		 ORDER BY id DESC LIMIT 1
	`).Scan(
		&evt.CreatedAt,
		&evt.Actor,
		&evt.Action,
		&evt.TargetType,
		&evt.TargetName,
		&evt.Status,
		&evt.Message,
		&evt.MetaJSON,
		&evt.ClientIP,
	); err != nil {
		t.Fatalf("load audit row: %v", err)
	}
	if evt.CreatedAt != "2026-05-17T12:34:56Z" {
		t.Fatalf("CreatedAt = %q, want fixed UTC timestamp", evt.CreatedAt)
	}
	if evt.Actor != "unknown" || evt.TargetName != "-" {
		t.Fatalf("defaults actor/target = %q/%q, want unknown/-", evt.Actor, evt.TargetName)
	}
	if len([]rune(evt.Action)) != 64 || len([]rune(evt.Status)) != 32 || len([]rune(evt.Message)) != auditMessageMaxLen || len([]rune(evt.ClientIP)) != 128 {
		t.Fatalf("unexpected truncation lengths: action=%d status=%d message=%d client_ip=%d", len([]rune(evt.Action)), len([]rune(evt.Status)), len([]rune(evt.Message)), len([]rune(evt.ClientIP)))
	}
	if len(evt.MetaJSON) > auditMetaMaxLen || !strings.Contains(evt.MetaJSON, `"_truncated":true`) || strings.Contains(evt.MetaJSON, "should-not-be-stored") {
		t.Fatalf("MetaJSON not sanitized/truncated as expected: len=%d body=%s", len(evt.MetaJSON), evt.MetaJSON)
	}
}

func TestAuditServiceRecordDoesNotNotifyWhenWriteFails(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close() error = %v", err)
	}

	var notifications []string
	svc := NewAuditService(func() *sql.DB { return db }, func(reason string) {
		notifications = append(notifications, reason)
	}, fixedAuditTimezone)

	if err := svc.Record("admin", "127.0.0.1", "server.update", "server", "srv", "success", "done", nil); err == nil {
		t.Fatalf("Record() error = nil, want write failure")
	}
	if len(notifications) != 0 {
		t.Fatalf("notifications = %v, want none after failed write", notifications)
	}
}

func TestAuditServiceListFiltersPaginatesAndFormatsTimezone(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "audit-service-list.db"))
	_ = getDB()

	svc := NewAuditService(getDB, nil, fixedAuditTimezone)
	base := time.Date(2026, 2, 10, 10, 0, 0, 0, time.UTC)
	seed := []AuditEvent{
		{CreatedAt: base.Add(-3 * time.Hour).Format(time.RFC3339), Actor: "admin", Action: "server.create", TargetType: "server", TargetName: "alpha", Status: "success", Message: "alpha-ok", MetaJSON: "{}"},
		{CreatedAt: base.Add(-2 * time.Hour).Format(time.RFC3339), Actor: "admin", Action: "server.update", TargetType: "server", TargetName: "beta", Status: "failure", Message: "beta-fail-1", MetaJSON: "{}"},
		{CreatedAt: base.Add(-1 * time.Hour).Format(time.RFC3339), Actor: "admin", Action: "server.update", TargetType: "server", TargetName: "beta", Status: "failure", Message: "beta-fail-2", MetaJSON: "{}"},
		{CreatedAt: base.Add(-30 * time.Minute).Format(time.RFC3339), Actor: "admin", Action: "server.update", TargetType: "server", TargetName: "beta", Status: "success", Message: "beta-ok", MetaJSON: "{}"},
	}
	for _, evt := range seed {
		if err := svc.Write(evt); err != nil {
			t.Fatalf("Write() seed error = %v", err)
		}
	}

	result, err := svc.List(AuditListFilter{
		Page:       1,
		PageSize:   1,
		TargetName: "beta",
		Action:     "server.update",
		Status:     "failure",
		From:       "2026-02-10T07:30:00Z",
		To:         "2026-02-10T09:30:00Z",
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if result.Total != 2 || result.Page != 1 || result.PageSize != 1 {
		t.Fatalf("unexpected list metadata: %+v", result)
	}
	if len(result.Items) != 1 || result.Items[0].Message != "beta-fail-2" {
		t.Fatalf("unexpected first page items: %+v", result.Items)
	}
	if !strings.Contains(result.Items[0].CreatedAtDisplay, "11:00:00 +02:00") {
		t.Fatalf("CreatedAtDisplay = %q, want +02:00 formatted display", result.Items[0].CreatedAtDisplay)
	}

	result, err = svc.List(AuditListFilter{Page: 1, PageSize: 500})
	if err != nil {
		t.Fatalf("List(page size cap) error = %v", err)
	}
	if result.PageSize != 200 {
		t.Fatalf("PageSize = %d, want 200 cap", result.PageSize)
	}
}

func TestAuditServicePruneDeletesOldEventsAndSkipsDuringMaintenance(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "audit-service-prune.db"))
	_ = getDB()

	svc := NewAuditService(getDB, nil, fixedAuditTimezone)
	svc.now = func() time.Time {
		return time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	}

	newEvt := AuditEvent{CreatedAt: "2026-05-16T12:00:00Z", Actor: "admin", Action: "server.create", TargetType: "server", TargetName: "srv-new", Status: "success", Message: "created", MetaJSON: "{}"}
	oldEvt := AuditEvent{CreatedAt: "2026-04-01T12:00:00Z", Actor: "admin", Action: "server.delete", TargetType: "server", TargetName: "srv-old", Status: "success", Message: "deleted", MetaJSON: "{}"}
	if err := svc.Write(newEvt); err != nil {
		t.Fatalf("Write(new) error = %v", err)
	}
	if err := svc.Write(oldEvt); err != nil {
		t.Fatalf("Write(old) error = %v", err)
	}

	setCurrentMaintenanceState(MaintenanceState{Active: true, Kind: jobKindBackupRestore, JobID: "job-maintenance"})
	if err := svc.Prune(30); err != nil {
		t.Fatalf("Prune(active maintenance) error = %v", err)
	}
	if got := countAuditEventsForTest(t); got != 2 {
		t.Fatalf("audit rows during maintenance = %d, want 2", got)
	}

	setCurrentMaintenanceState(MaintenanceState{})
	if err := svc.Prune(30); err != nil {
		t.Fatalf("Prune() error = %v", err)
	}
	if got := countAuditEventsForTest(t); got != 1 {
		t.Fatalf("audit rows after prune = %d, want 1", got)
	}
}

func TestAuditServiceMarkdownReports(t *testing.T) {
	svc := NewAuditService(nil, nil, fixedAuditTimezone)

	auditBody := svc.BuildAuditMarkdownReport(AuditEvent{
		ID:         42,
		CreatedAt:  "2026-05-17T12:00:00Z",
		Actor:      "admin",
		Action:     "server.update",
		TargetType: "server",
		TargetName: "srv",
		Status:     "success",
		Message:    "done",
		MetaJSON:   `{"execution_duration_ms":1234}`,
		ClientIP:   "127.0.0.1",
	})
	for _, want := range []string{"# Audit Event Report #42", "- Client IP: 127.0.0.1", `"execution_duration_ms": 1234`} {
		if !strings.Contains(auditBody, want) {
			t.Fatalf("audit report missing %q:\n%s", want, auditBody)
		}
	}

	jobBody := svc.BuildJobMarkdownReport(JobRecord{
		ID:              "job-42",
		Kind:            jobKindUpdate,
		ServerName:      "srv",
		Actor:           "admin",
		Status:          jobStatusSucceeded,
		Phase:           jobPhaseComplete,
		Summary:         "Update completed",
		LogsText:        "Upgrade completed.",
		RetryPolicyJSON: `{"max_attempts":3}`,
		MetaJSON:        `{"server":"srv"}`,
		CreatedAt:       "2026-05-17T12:00:00Z",
		UpdatedAt:       "2026-05-17T12:01:00Z",
		StartedAt:       "2026-05-17T12:00:05Z",
		FinishedAt:      "2026-05-17T12:00:55Z",
	})
	for _, want := range []string{"# Update Job Report job-42", "- Started: 2026-05-17T12:00:05Z", `"max_attempts": 3`, "Upgrade completed."} {
		if !strings.Contains(jobBody, want) {
			t.Fatalf("job report missing %q:\n%s", want, jobBody)
		}
	}
}

func fixedAuditTimezone() (*time.Location, string) {
	return time.FixedZone("+02:00", 2*60*60), "+02:00"
}

func countAuditEventsForTest(t *testing.T) int {
	t.Helper()
	var count int
	if err := getDB().QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&count); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	return count
}
