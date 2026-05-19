package audit

import "database/sql"

func EnsureSchema(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_events (
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
		)
	`); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events (created_at DESC)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_events (target_type, target_name, created_at DESC)"); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events (action, created_at DESC)"); err != nil {
		return err
	}
	return nil
}
