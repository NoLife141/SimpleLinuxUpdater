package servers

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openSchemaTestDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSchemaCreatesServersTableAndIsIdempotent(t *testing.T) {
	db := openSchemaTestDB(t, "servers-schema.db")
	for i := 0; i < 2; i++ {
		if err := EnsureSchema(db); err != nil {
			t.Fatalf("EnsureSchema run %d error = %v", i+1, err)
		}
	}
	assertColumnsExist(t, db, "servers", "name", "host", "port", "user", "pass_enc", "key_enc", "key_path", "tags")
}

func TestSchemaMigratesLegacyServersColumns(t *testing.T) {
	db := openSchemaTestDB(t, "servers-legacy.db")
	if _, err := db.Exec(`
		CREATE TABLE servers (
			name TEXT PRIMARY KEY,
			host TEXT NOT NULL,
			user TEXT NOT NULL,
			pass_enc TEXT NOT NULL
		)
	`); err != nil {
		t.Fatalf("create legacy servers table: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema() error = %v", err)
	}
	assertColumnsExist(t, db, "servers", "port", "key_enc", "key_path", "tags")
}

func assertColumnsExist(t *testing.T, db *sql.DB, table string, names ...string) {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s) error = %v", table, err)
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
			t.Fatalf("table %s missing column %s; columns=%v", table, name, seen)
		}
	}
}
