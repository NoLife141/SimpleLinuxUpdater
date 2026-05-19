package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSchemaInitializesDomainTables(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "domain-schema.db"))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for i := 0; i < 2; i++ {
		if err := ensureSchema(db); err != nil {
			t.Fatalf("ensureSchema run %d error = %v", i+1, err)
		}
	}
	for _, table := range []string{
		"servers",
		"settings",
		"auth_users",
		"sessions",
		"audit_events",
		"server_facts",
		"jobs",
		"update_policies",
		"update_policy_overrides",
		"update_policy_runs",
	} {
		if !schemaTableExists(t, db, table) {
			t.Fatalf("table %s was not initialized", table)
		}
	}
}

func schemaTableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = ?", name).Scan(&count); err != nil {
		t.Fatalf("count table %s: %v", name, err)
	}
	return count > 0
}
