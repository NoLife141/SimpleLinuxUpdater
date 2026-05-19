package servers

import (
	"database/sql"
)

func EnsureSchema(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS servers (
			name TEXT PRIMARY KEY,
			host TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 22,
			user TEXT NOT NULL,
			pass_enc TEXT NOT NULL,
			key_enc TEXT NOT NULL DEFAULT '',
			key_path TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT ''
		)
	`); err != nil {
		return err
	}
	rows, err := db.Query("PRAGMA table_info(servers)")
	if err != nil {
		return err
	}
	defer rows.Close()
	hasKeyPath := false
	hasKeyEnc := false
	hasTags := false
	hasPort := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "key_path" {
			hasKeyPath = true
		}
		if name == "key_enc" {
			hasKeyEnc = true
		}
		if name == "tags" {
			hasTags = true
		}
		if name == "port" {
			hasPort = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasKeyPath {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN key_path TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !hasKeyEnc {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN key_enc TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !hasTags {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN tags TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !hasPort {
		if _, err := db.Exec("ALTER TABLE servers ADD COLUMN port INTEGER NOT NULL DEFAULT 22"); err != nil {
			return err
		}
	}
	return nil
}
