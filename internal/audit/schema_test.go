package audit

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSchemaCreatesAuditTableIndexesAndIsIdempotent(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit-schema.db"))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for i := 0; i < 2; i++ {
		if err := EnsureSchema(db); err != nil {
			t.Fatalf("EnsureSchema run %d error = %v", i+1, err)
		}
	}
	assertAuditColumnsExist(t, db, "id", "created_at", "actor", "action", "target_type", "target_name", "status", "message", "meta_json", "request_id", "client_ip")
	for _, name := range []string{"idx_audit_created_at", "idx_audit_target", "idx_audit_action"} {
		if !auditIndexExists(t, db, name) {
			t.Fatalf("audit index %s was not created", name)
		}
	}
}

func assertAuditColumnsExist(t *testing.T, db *sql.DB, names ...string) {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(audit_events)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(audit_events) error = %v", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns: %v", err)
	}
	for _, name := range names {
		if !seen[name] {
			t.Fatalf("audit_events missing column %s; columns=%v", name, seen)
		}
	}
}

func auditIndexExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(1) FROM sqlite_master WHERE type = 'index' AND name = ?", name).Scan(&count); err != nil {
		t.Fatalf("count index %s: %v", name, err)
	}
	return count > 0
}
