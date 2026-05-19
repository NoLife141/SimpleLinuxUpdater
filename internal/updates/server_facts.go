package updates

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

type ServerFactsRepository interface {
	Save(ServerFactsRecord) error
	LoadAll() (map[string]ServerFactsRecord, error)
	RenameServerTx(*sql.Tx, string, string) error
	DeleteServerTx(*sql.Tx, string) error
}

type SQLiteServerFactsRepository struct {
	DB  func() *sql.DB
	Now func() time.Time
}

func (r SQLiteServerFactsRepository) dbConn() *sql.DB {
	if r.DB != nil {
		return r.DB()
	}
	return nil
}

func (r SQLiteServerFactsRepository) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

func EnsureServerFactsSchema(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS server_facts (
			server_name TEXT PRIMARY KEY,
			collected_at TEXT NOT NULL,
			os_pretty_name TEXT NOT NULL DEFAULT '',
			uptime_seconds INTEGER NOT NULL DEFAULT 0,
			disk_status TEXT NOT NULL DEFAULT 'unknown',
			disk_free_kb INTEGER NOT NULL DEFAULT 0,
			disk_details TEXT NOT NULL DEFAULT '',
			apt_status TEXT NOT NULL DEFAULT 'unknown',
			apt_details TEXT NOT NULL DEFAULT '',
			reboot_required INTEGER,
			raw_json TEXT NOT NULL DEFAULT '{}'
		)
	`); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_server_facts_collected_at ON server_facts (collected_at DESC)"); err != nil {
		return err
	}
	return nil
}

func (r SQLiteServerFactsRepository) Save(record ServerFactsRecord) error {
	db := r.dbConn()
	if db == nil {
		return errors.New("database is not initialized")
	}
	record.ServerName = strings.TrimSpace(record.ServerName)
	if record.ServerName == "" {
		return errors.New("server name is required")
	}
	if strings.TrimSpace(record.CollectedAt) == "" {
		record.CollectedAt = r.now().UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(record.DiskStatus) == "" {
		record.DiskStatus = "unknown"
	}
	if strings.TrimSpace(record.AptStatus) == "" {
		record.AptStatus = "unknown"
	}
	if strings.TrimSpace(record.RawJSON) == "" {
		record.RawJSON = "{}"
	}
	var rebootValue any
	if record.RebootRequired != nil {
		rebootValue = boolToInt(*record.RebootRequired)
	}
	_, err := db.Exec(`
		INSERT INTO server_facts (
			server_name, collected_at, os_pretty_name, uptime_seconds,
			disk_status, disk_free_kb, disk_details, apt_status, apt_details,
			reboot_required, raw_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(server_name) DO UPDATE SET
			collected_at = excluded.collected_at,
			os_pretty_name = excluded.os_pretty_name,
			uptime_seconds = excluded.uptime_seconds,
			disk_status = excluded.disk_status,
			disk_free_kb = excluded.disk_free_kb,
			disk_details = excluded.disk_details,
			apt_status = excluded.apt_status,
			apt_details = excluded.apt_details,
			reboot_required = excluded.reboot_required,
			raw_json = excluded.raw_json
	`,
		record.ServerName,
		record.CollectedAt,
		record.OSPrettyName,
		record.UptimeSeconds,
		record.DiskStatus,
		record.DiskFreeKB,
		record.DiskDetails,
		record.AptStatus,
		record.AptDetails,
		rebootValue,
		record.RawJSON,
	)
	return err
}

func (r SQLiteServerFactsRepository) LoadAll() (map[string]ServerFactsRecord, error) {
	db := r.dbConn()
	if db == nil {
		return nil, errors.New("database is not initialized")
	}
	rows, err := db.Query(`
		SELECT server_name, collected_at, os_pretty_name, uptime_seconds,
		       disk_status, disk_free_kb, disk_details, apt_status, apt_details,
		       reboot_required, raw_json
		  FROM server_facts
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := map[string]ServerFactsRecord{}
	for rows.Next() {
		var record ServerFactsRecord
		var reboot sql.NullInt64
		if err := rows.Scan(
			&record.ServerName,
			&record.CollectedAt,
			&record.OSPrettyName,
			&record.UptimeSeconds,
			&record.DiskStatus,
			&record.DiskFreeKB,
			&record.DiskDetails,
			&record.AptStatus,
			&record.AptDetails,
			&reboot,
			&record.RawJSON,
		); err != nil {
			return nil, err
		}
		if reboot.Valid {
			required := reboot.Int64 != 0
			record.RebootRequired = &required
		}
		records[record.ServerName] = record
	}
	return records, rows.Err()
}

func (r SQLiteServerFactsRepository) RenameServerTx(tx *sql.Tx, oldName, newName string) error {
	if strings.TrimSpace(oldName) == "" || strings.TrimSpace(newName) == "" || oldName == newName {
		return nil
	}
	_, err := tx.Exec("UPDATE server_facts SET server_name = ? WHERE server_name = ?", newName, oldName)
	return err
}

func (r SQLiteServerFactsRepository) DeleteServerTx(tx *sql.Tx, name string) error {
	_, err := tx.Exec("DELETE FROM server_facts WHERE server_name = ?", name)
	return err
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
