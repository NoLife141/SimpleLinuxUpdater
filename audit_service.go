package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

type auditDBProvider func() *sql.DB

type auditNotifier func(string)

type auditTimezoneProvider func() (*time.Location, string)

type AuditService struct {
	db       auditDBProvider
	notify   auditNotifier
	timezone auditTimezoneProvider
	now      func() time.Time
}

type AuditListFilter struct {
	Page       int
	PageSize   int
	TargetName string
	Action     string
	Status     string
	From       string
	To         string
}

type AuditListResult struct {
	Items    []AuditEvent `json:"items"`
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
	Total    int          `json:"total"`
}

type AuditListError struct {
	Stage string
	Err   error
}

func (e *AuditListError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *AuditListError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

var auditService = NewAuditService(getDB, notifyDashboardEvent, currentAppTimezone)

func NewAuditService(db auditDBProvider, notify auditNotifier, timezone auditTimezoneProvider) *AuditService {
	if db == nil {
		db = getDB
	}
	if timezone == nil {
		timezone = currentAppTimezone
	}
	return &AuditService{
		db:       db,
		notify:   notify,
		timezone: timezone,
		now:      time.Now,
	}
}

func (s *AuditService) Write(evt AuditEvent) error {
	db := s.db()
	_, err := db.Exec(
		`INSERT INTO audit_events (created_at, actor, action, target_type, target_name, status, message, meta_json, request_id, client_ip)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		evt.CreatedAt,
		evt.Actor,
		evt.Action,
		evt.TargetType,
		evt.TargetName,
		evt.Status,
		evt.Message,
		evt.MetaJSON,
		evt.RequestID,
		evt.ClientIP,
	)
	return err
}

func (s *AuditService) Record(actor, clientIP, action, targetType, targetName, status, message string, meta map[string]any) error {
	evt := AuditEvent{
		CreatedAt:  s.now().UTC().Format(time.RFC3339),
		Actor:      truncateString(actor, 128),
		Action:     truncateString(action, 64),
		TargetType: truncateString(targetType, 64),
		TargetName: truncateString(targetName, 255),
		Status:     truncateString(status, 32),
		Message:    truncateString(message, auditMessageMaxLen),
		MetaJSON:   sanitizeAuditMeta(meta),
		RequestID:  "",
		ClientIP:   truncateString(clientIP, 128),
	}
	if evt.Actor == "" {
		evt.Actor = "unknown"
	}
	if evt.TargetName == "" {
		evt.TargetName = "-"
	}
	if err := s.Write(evt); err != nil {
		return err
	}
	if s.notify != nil {
		s.notify(action)
	}
	return nil
}

func (s *AuditService) List(filter AuditListFilter) (AuditListResult, error) {
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	offset := (page - 1) * pageSize

	var whereParts []string
	var args []any
	if filter.TargetName != "" {
		whereParts = append(whereParts, "target_name = ?")
		args = append(args, filter.TargetName)
	}
	if filter.Action != "" {
		whereParts = append(whereParts, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.Status != "" {
		whereParts = append(whereParts, "status = ?")
		args = append(args, filter.Status)
	}
	if filter.From != "" {
		whereParts = append(whereParts, "created_at >= ?")
		args = append(args, filter.From)
	}
	if filter.To != "" {
		whereParts = append(whereParts, "created_at <= ?")
		args = append(args, filter.To)
	}

	whereClause := ""
	if len(whereParts) > 0 {
		whereClause = " WHERE " + strings.Join(whereParts, " AND ")
	}

	db := s.db()
	countQuery := "SELECT COUNT(*) FROM audit_events" + whereClause
	var total int
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return AuditListResult{}, &AuditListError{Stage: "count", Err: err}
	}

	query := `SELECT id, created_at, actor, action, target_type, target_name, status, message, meta_json, request_id, client_ip
			FROM audit_events` + whereClause + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	queryArgs := append(append([]any{}, args...), pageSize, offset)
	loc, timezoneName := s.timezone()
	rows, err := db.Query(query, queryArgs...)
	if err != nil {
		return AuditListResult{}, &AuditListError{Stage: "load", Err: err}
	}
	defer rows.Close()

	items := make([]AuditEvent, 0, pageSize)
	for rows.Next() {
		var evt AuditEvent
		if err := rows.Scan(
			&evt.ID,
			&evt.CreatedAt,
			&evt.Actor,
			&evt.Action,
			&evt.TargetType,
			&evt.TargetName,
			&evt.Status,
			&evt.Message,
			&evt.MetaJSON,
			&evt.RequestID,
			&evt.ClientIP,
		); err != nil {
			return AuditListResult{}, &AuditListError{Stage: "parse", Err: err}
		}
		evt.CreatedAtDisplay, _ = formatTimestampForAppDisplayWithTimezone(evt.CreatedAt, loc, timezoneName)
		items = append(items, evt)
	}
	if err := rows.Err(); err != nil {
		return AuditListResult{}, &AuditListError{Stage: "iterate", Err: err}
	}

	return AuditListResult{
		Items:    items,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	}, nil
}

func (s *AuditService) LoadByID(id string) (AuditEvent, error) {
	var evt AuditEvent
	err := s.db().QueryRow(`
		SELECT id, created_at, actor, action, target_type, target_name, status, message, meta_json, request_id, client_ip
		  FROM audit_events
		 WHERE id = ?
	`, strings.TrimSpace(id)).Scan(
		&evt.ID,
		&evt.CreatedAt,
		&evt.Actor,
		&evt.Action,
		&evt.TargetType,
		&evt.TargetName,
		&evt.Status,
		&evt.Message,
		&evt.MetaJSON,
		&evt.RequestID,
		&evt.ClientIP,
	)
	return evt, err
}

func (s *AuditService) Prune(retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	// Check maintenance before taking backupRestoreMu to avoid unnecessary lock
	// contention, then re-check after backupRestoreMu.RLock() because maintenance
	// can become active in the gap between the first currentMaintenanceState()
	// read and acquiring backupRestoreMu.
	if currentMaintenanceState().Active {
		return nil
	}
	backupRestoreMu.RLock()
	defer backupRestoreMu.RUnlock()
	if currentMaintenanceState().Active {
		return nil
	}
	cutoff := s.now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	_, err := s.db().Exec("DELETE FROM audit_events WHERE created_at < ?", cutoff)
	return err
}

func (s *AuditService) BuildAuditMarkdownReport(evt AuditEvent) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Audit Event Report #%d\n\n", evt.ID)
	fmt.Fprintf(&buf, "- Time: %s\n", evt.CreatedAt)
	fmt.Fprintf(&buf, "- Actor: %s\n", evt.Actor)
	fmt.Fprintf(&buf, "- Action: %s\n", evt.Action)
	fmt.Fprintf(&buf, "- Target: %s/%s\n", evt.TargetType, evt.TargetName)
	fmt.Fprintf(&buf, "- Status: %s\n", evt.Status)
	fmt.Fprintf(&buf, "- Message: %s\n", evt.Message)
	if strings.TrimSpace(evt.ClientIP) != "" {
		fmt.Fprintf(&buf, "- Client IP: %s\n", evt.ClientIP)
	}
	appendJSONBlock(&buf, "Metadata", evt.MetaJSON)
	return buf.String()
}

func (s *AuditService) BuildJobMarkdownReport(job JobRecord) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Update Job Report %s\n\n", job.ID)
	fmt.Fprintf(&buf, "- Kind: %s\n", job.Kind)
	fmt.Fprintf(&buf, "- Server: %s\n", job.ServerName)
	fmt.Fprintf(&buf, "- Actor: %s\n", job.Actor)
	fmt.Fprintf(&buf, "- Status: %s\n", job.Status)
	fmt.Fprintf(&buf, "- Phase: %s\n", job.Phase)
	fmt.Fprintf(&buf, "- Summary: %s\n", job.Summary)
	fmt.Fprintf(&buf, "- Created: %s\n", job.CreatedAt)
	fmt.Fprintf(&buf, "- Updated: %s\n", job.UpdatedAt)
	if strings.TrimSpace(job.StartedAt) != "" {
		fmt.Fprintf(&buf, "- Started: %s\n", job.StartedAt)
	}
	if strings.TrimSpace(job.FinishedAt) != "" {
		fmt.Fprintf(&buf, "- Finished: %s\n", job.FinishedAt)
	}
	if strings.TrimSpace(job.ErrorClass) != "" {
		fmt.Fprintf(&buf, "- Error class: %s\n", job.ErrorClass)
	}
	appendJSONBlock(&buf, "Retry Policy", job.RetryPolicyJSON)
	appendJSONBlock(&buf, "Metadata", job.MetaJSON)
	fmt.Fprintf(&buf, "\n## Logs\n\n```text\n%s\n```\n", strings.TrimSpace(job.LogsText))
	return buf.String()
}

func appendJSONBlock(buf *bytes.Buffer, title, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "{}"
	}
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
		if pretty, marshalErr := json.MarshalIndent(parsed, "", "  "); marshalErr == nil {
			raw = string(pretty)
		}
	}
	fmt.Fprintf(buf, "\n## %s\n\n```json\n%s\n```\n", title, raw)
}

func writeAuditEvent(evt AuditEvent) error {
	return auditService.Write(evt)
}

func auditWithActor(actor, clientIP, action, targetType, targetName, status, message string, meta map[string]any) {
	if err := auditService.Record(actor, clientIP, action, targetType, targetName, status, message, meta); err != nil {
		log.Printf("audit write failed: action=%s target=%s err=%v", action, targetName, err)
	}
}

func pruneAuditEvents(retentionDays int) error {
	return auditService.Prune(retentionDays)
}
