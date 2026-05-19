package auth

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openAuthSchemaTestDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSchemaCreatesAuthTablesAndIsIdempotent(t *testing.T) {
	db := openAuthSchemaTestDB(t, "auth-schema.db")
	for i := 0; i < 2; i++ {
		if err := EnsureSchema(db); err != nil {
			t.Fatalf("EnsureSchema run %d error = %v", i+1, err)
		}
	}
	assertAuthColumnsExist(t, db, "auth_users", "id", "username", "password_hash", "created_at", "updated_at")
	assertAuthColumnsExist(t, db, "sessions", "token", "data", "expiry")
	if !authIndexExists(t, db, "sessions_expiry_idx") {
		t.Fatalf("sessions_expiry_idx was not created")
	}
}

func TestSchemaMigratesLegacySessionExpiry(t *testing.T) {
	db := openAuthSchemaTestDB(t, "auth-legacy-session.db")
	if _, err := db.Exec(`
		CREATE TABLE sessions (
			token TEXT PRIMARY KEY,
			data BLOB NOT NULL,
			expires TEXT NOT NULL
		);
		INSERT INTO sessions(token, data, expires) VALUES('tok', x'00', '123')
	`); err != nil {
		t.Fatalf("create legacy sessions table: %v", err)
	}
	if err := EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema() error = %v", err)
	}
	assertAuthColumnsExist(t, db, "sessions", "expiry")
	var expiry float64
	if err := db.QueryRow("SELECT expiry FROM sessions WHERE token = 'tok'").Scan(&expiry); err != nil {
		t.Fatalf("load migrated expiry: %v", err)
	}
	if expiry != 123 {
		t.Fatalf("expiry = %v, want 123", expiry)
	}
}

func assertAuthColumnsExist(t *testing.T, db *sql.DB, table string, names ...string) {
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

func authIndexExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(1) FROM sqlite_master WHERE type = 'index' AND name = ?", name).Scan(&count); err != nil {
		t.Fatalf("count index %s: %v", name, err)
	}
	return count > 0
}
