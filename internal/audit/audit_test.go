package audit

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"debian-updater/internal/jobs"

	_ "modernc.org/sqlite"
)

func TestServiceRecordSanitizesTruncatesAndNotifies(t *testing.T) {
	db := newTestDB(t)

	var notifications []string
	svc := NewService(ServiceOptions{
		DB: func() *sql.DB { return db },
		Notify: func(reason string) {
			notifications = append(notifications, reason)
		},
		Timezone: fixedTimezone,
		Now: func() time.Time {
			return time.Date(2026, 5, 17, 12, 34, 56, 0, time.UTC)
		},
	})

	longAction := strings.Repeat("a", 80)
	longStatus := strings.Repeat("s", 40)
	longClientIP := strings.Repeat("1", 150)
	longMessage := strings.Repeat("m", MessageMaxLen+20)
	meta := map[string]any{
		"safe":     strings.Repeat("x", MetaMaxLen*2),
		"password": "should-not-be-stored",
	}

	if err := svc.Record("", longClientIP, longAction, "server", "", longStatus, longMessage, meta); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(notifications) != 1 || notifications[0] != longAction {
		t.Fatalf("notifications = %v, want raw action once", notifications)
	}

	var evt Event
	if err := db.QueryRow(`
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
	if len([]rune(evt.Action)) != 64 || len([]rune(evt.Status)) != 32 || len([]rune(evt.Message)) != MessageMaxLen || len([]rune(evt.ClientIP)) != 128 {
		t.Fatalf("unexpected truncation lengths: action=%d status=%d message=%d client_ip=%d", len([]rune(evt.Action)), len([]rune(evt.Status)), len([]rune(evt.Message)), len([]rune(evt.ClientIP)))
	}
	if len(evt.MetaJSON) > MetaMaxLen || !strings.Contains(evt.MetaJSON, `"_truncated":true`) || strings.Contains(evt.MetaJSON, "should-not-be-stored") {
		t.Fatalf("MetaJSON not sanitized/truncated as expected: len=%d body=%s", len(evt.MetaJSON), evt.MetaJSON)
	}
}

func TestServiceRecordDoesNotNotifyWhenWriteFails(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close() error = %v", err)
	}

	var notifications []string
	svc := NewService(ServiceOptions{
		DB:       func() *sql.DB { return db },
		Notify:   func(reason string) { notifications = append(notifications, reason) },
		Timezone: fixedTimezone,
	})

	if err := svc.Record("admin", "127.0.0.1", "server.update", "server", "srv", "success", "done", nil); err == nil {
		t.Fatalf("Record() error = nil, want write failure")
	}
	if len(notifications) != 0 {
		t.Fatalf("notifications = %v, want none after failed write", notifications)
	}
}

func TestServiceListFiltersPaginatesAndFormatsTimezone(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(ServiceOptions{
		DB:       func() *sql.DB { return db },
		Timezone: fixedTimezone,
	})
	base := time.Date(2026, 2, 10, 10, 0, 0, 0, time.UTC)
	seed := []Event{
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

	result, err := svc.List(ListFilter{
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

	result, err = svc.List(ListFilter{Page: 1, PageSize: 500})
	if err != nil {
		t.Fatalf("List(page size cap) error = %v", err)
	}
	if result.PageSize != 200 {
		t.Fatalf("PageSize = %d, want 200 cap", result.PageSize)
	}
}

func TestServicePruneDeletesOldEventsAndRespectsGuard(t *testing.T) {
	db := newTestDB(t)
	pruneAllowed := false
	svc := NewService(ServiceOptions{
		DB: func() *sql.DB { return db },
		Now: func() time.Time {
			return time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
		},
		PruneAllowed: func() bool { return pruneAllowed },
		Timezone:     fixedTimezone,
	})

	newEvt := Event{CreatedAt: "2026-05-16T12:00:00Z", Actor: "admin", Action: "server.create", TargetType: "server", TargetName: "srv-new", Status: "success", Message: "created", MetaJSON: "{}"}
	oldEvt := Event{CreatedAt: "2026-04-01T12:00:00Z", Actor: "admin", Action: "server.delete", TargetType: "server", TargetName: "srv-old", Status: "success", Message: "deleted", MetaJSON: "{}"}
	if err := svc.Write(newEvt); err != nil {
		t.Fatalf("Write(new) error = %v", err)
	}
	if err := svc.Write(oldEvt); err != nil {
		t.Fatalf("Write(old) error = %v", err)
	}

	if err := svc.Prune(30); err != nil {
		t.Fatalf("Prune(blocked) error = %v", err)
	}
	if got := countAuditEvents(t, db); got != 2 {
		t.Fatalf("audit rows while blocked = %d, want 2", got)
	}

	pruneAllowed = true
	if err := svc.Prune(30); err != nil {
		t.Fatalf("Prune() error = %v", err)
	}
	if got := countAuditEvents(t, db); got != 1 {
		t.Fatalf("audit rows after prune = %d, want 1", got)
	}
}

func TestServicePruneRunsDeleteInsidePruneGuard(t *testing.T) {
	repo := &guardedPruneRepository{}
	inGuard := false
	svc := NewService(ServiceOptions{
		Repository: repo,
		Now: func() time.Time {
			return time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
		},
		PruneGuard: func(prune func() error) error {
			inGuard = true
			defer func() { inGuard = false }()
			return prune()
		},
	})
	repo.pruneCheck = func(cutoff string) {
		if !inGuard {
			t.Fatalf("PruneBefore called outside PruneGuard")
		}
		if cutoff != "2026-04-17T12:00:00Z" {
			t.Fatalf("cutoff = %q, want fixed retention cutoff", cutoff)
		}
	}

	if err := svc.Prune(30); err != nil {
		t.Fatalf("Prune() error = %v", err)
	}
	if repo.pruneCalls != 1 {
		t.Fatalf("PruneBefore calls = %d, want 1", repo.pruneCalls)
	}
}

func TestServiceMarkdownReports(t *testing.T) {
	svc := NewService(ServiceOptions{Timezone: fixedTimezone})

	auditBody := svc.BuildAuditMarkdownReport(Event{
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

	jobBody := svc.BuildJobMarkdownReport(jobs.Record{
		ID:              "job-42",
		Kind:            jobs.KindUpdate,
		ServerName:      "srv",
		Actor:           "admin",
		Status:          jobs.StatusSucceeded,
		Phase:           jobs.PhaseComplete,
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

type guardedPruneRepository struct {
	pruneCalls int
	pruneCheck func(string)
}

func (r *guardedPruneRepository) Write(Event) error {
	return nil
}

func (r *guardedPruneRepository) Count(ListFilter) (int, error) {
	return 0, nil
}

func (r *guardedPruneRepository) List(ListFilter, int, int) ([]Event, error) {
	return nil, nil
}

func (r *guardedPruneRepository) LoadByID(string) (Event, error) {
	return Event{}, sql.ErrNoRows
}

func (r *guardedPruneRepository) PruneBefore(cutoff string) error {
	r.pruneCalls++
	if r.pruneCheck != nil {
		r.pruneCheck(cutoff)
	}
	return nil
}

func fixedTimezone() (*time.Location, string) {
	return time.FixedZone("+02:00", 2*60*60), "+02:00"
}

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("db.Close() error = %v", err)
		}
	})
	ensureTestSchema(t, db)
	return db
}

func ensureTestSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS audit_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		created_at TEXT NOT NULL,
		actor TEXT NOT NULL,
		action TEXT NOT NULL,
		target_type TEXT NOT NULL,
		target_name TEXT NOT NULL,
		status TEXT NOT NULL,
		message TEXT NOT NULL,
		meta_json TEXT NOT NULL DEFAULT '{}',
		request_id TEXT NOT NULL DEFAULT '',
		client_ip TEXT NOT NULL DEFAULT ''
	)`)
	if err != nil {
		t.Fatalf("create audit_events schema: %v", err)
	}
}

func countAuditEvents(t *testing.T, db *sql.DB) int {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&count); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	return count
}
