package updates

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestServerFactsRepositorySchemaAndRoundTrip(t *testing.T) {
	db, repo := openServerFactsTestRepository(t, "server-facts.db")
	for i := 0; i < 2; i++ {
		if err := EnsureServerFactsSchema(db); err != nil {
			t.Fatalf("EnsureServerFactsSchema run %d error = %v", i+1, err)
		}
	}
	rebootRequired := true
	record := ServerFactsRecord{
		ServerName:     "srv-a",
		CollectedAt:    "2026-05-18T12:00:00Z",
		OSPrettyName:   "Ubuntu 24.04",
		UptimeSeconds:  42,
		DiskStatus:     "ok",
		DiskFreeKB:     1234,
		DiskDetails:    "disk ok",
		AptStatus:      "ok",
		AptDetails:     "apt ok",
		RebootRequired: &rebootRequired,
		RawJSON:        `{"source":"test"}`,
	}
	if err := repo.Save(record); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	loaded, err := repo.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}
	got := loaded["srv-a"]
	if got.ServerName != record.ServerName || got.OSPrettyName != record.OSPrettyName || got.RawJSON != record.RawJSON {
		t.Fatalf("loaded record = %+v, want %+v", got, record)
	}
	if got.RebootRequired == nil || !*got.RebootRequired {
		t.Fatalf("reboot_required = %v, want true", got.RebootRequired)
	}
}

func TestServerFactsRepositoryRenameAndDeleteTx(t *testing.T) {
	_, repo := openServerFactsTestRepository(t, "server-facts-tx.db")
	if err := repo.Save(ServerFactsRecord{ServerName: "old", CollectedAt: "2026-05-18T12:00:00Z"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	tx, err := repo.dbConn().Begin()
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if err := repo.RenameServerTx(tx, "old", "new"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("RenameServerTx() error = %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("rename commit error = %v", err)
	}
	loaded, err := repo.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() after rename error = %v", err)
	}
	if _, ok := loaded["new"]; !ok {
		t.Fatalf("renamed record missing: %+v", loaded)
	}
	tx, err = repo.dbConn().Begin()
	if err != nil {
		t.Fatalf("Begin delete tx error = %v", err)
	}
	if err := repo.DeleteServerTx(tx, "new"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("DeleteServerTx() error = %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("delete commit error = %v", err)
	}
	loaded, err = repo.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() after delete error = %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("records after delete = %+v, want empty", loaded)
	}
}

func TestServerFactsRepositoryDefaultsCollectedAt(t *testing.T) {
	_, repo := openServerFactsTestRepository(t, "server-facts-default-time.db")
	now := time.Date(2026, 5, 18, 12, 34, 56, 0, time.UTC)
	repo.Now = func() time.Time { return now }
	if err := repo.Save(ServerFactsRecord{ServerName: "srv-time"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	loaded, err := repo.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}
	if got := loaded["srv-time"].CollectedAt; got != "2026-05-18T12:34:56Z" {
		t.Fatalf("CollectedAt = %q, want default timestamp", got)
	}
}

func openServerFactsTestRepository(t *testing.T, name string) (*sql.DB, SQLiteServerFactsRepository) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureServerFactsSchema(db); err != nil {
		t.Fatalf("EnsureServerFactsSchema() error = %v", err)
	}
	return db, SQLiteServerFactsRepository{DB: func() *sql.DB { return db }}
}
