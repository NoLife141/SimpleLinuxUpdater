package audit

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"debian-updater/internal/jobs"
)

const (
	MessageMaxLen = 512
	MetaMaxLen    = 2048
)

type DBProvider func() *sql.DB

type Notifier func(string)

type TimezoneProvider func() (*time.Location, string)

type DisplayFormatter func(raw string, loc *time.Location, timezoneName string) (string, string)

type Event struct {
	ID               int64  `json:"id"`
	CreatedAt        string `json:"created_at"`
	CreatedAtDisplay string `json:"created_at_display,omitempty"`
	Actor            string `json:"actor"`
	Action           string `json:"action"`
	TargetType       string `json:"target_type"`
	TargetName       string `json:"target_name"`
	Status           string `json:"status"`
	Message          string `json:"message"`
	MetaJSON         string `json:"meta_json"`
	RequestID        string `json:"request_id"`
	ClientIP         string `json:"client_ip"`
}

type ListFilter struct {
	Page       int
	PageSize   int
	TargetName string
	Action     string
	Status     string
	From       string
	To         string
}

type ListResult struct {
	Items    []Event `json:"items"`
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
	Total    int     `json:"total"`
}

type ListError struct {
	Stage string
	Err   error
}

func (e *ListError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ListError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type Repository interface {
	Write(Event) error
	Count(ListFilter) (int, error)
	List(ListFilter, int, int) ([]Event, error)
	LoadByID(string) (Event, error)
	PruneBefore(string) error
}

type SQLiteRepository struct {
	db DBProvider
}

func NewSQLiteRepository(db DBProvider) *SQLiteRepository {
	return &SQLiteRepository{db: db}
}

func (r *SQLiteRepository) Write(evt Event) error {
	db := r.db()
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

func (r *SQLiteRepository) Count(filter ListFilter) (int, error) {
	whereClause, args := auditWhereClause(filter)
	var total int
	err := r.db().QueryRow("SELECT COUNT(*) FROM audit_events"+whereClause, args...).Scan(&total)
	return total, err
}

func (r *SQLiteRepository) List(filter ListFilter, limit, offset int) ([]Event, error) {
	whereClause, args := auditWhereClause(filter)
	query := `SELECT id, created_at, actor, action, target_type, target_name, status, message, meta_json, request_id, client_ip
			FROM audit_events` + whereClause + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	queryArgs := append(append([]any{}, args...), limit, offset)
	rows, err := r.db().Query(query, queryArgs...)
	if err != nil {
		return nil, &ListError{Stage: "load", Err: err}
	}
	defer rows.Close()

	items := make([]Event, 0, limit)
	for rows.Next() {
		var evt Event
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
			return nil, &ListError{Stage: "parse", Err: err}
		}
		items = append(items, evt)
	}
	if err := rows.Err(); err != nil {
		return nil, &ListError{Stage: "iterate", Err: err}
	}
	return items, nil
}

func (r *SQLiteRepository) LoadByID(id string) (Event, error) {
	var evt Event
	err := r.db().QueryRow(`
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

func (r *SQLiteRepository) PruneBefore(cutoff string) error {
	_, err := r.db().Exec("DELETE FROM audit_events WHERE created_at < ?", cutoff)
	return err
}

func auditWhereClause(filter ListFilter) (string, []any) {
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
	if len(whereParts) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(whereParts, " AND "), args
}

type ServiceOptions struct {
	DB            DBProvider
	Repository    Repository
	Notify        Notifier
	Timezone      TimezoneProvider
	FormatDisplay DisplayFormatter
	PruneAllowed  func() bool
	Now           func() time.Time
}

type Service struct {
	repo          Repository
	notify        Notifier
	timezone      TimezoneProvider
	formatDisplay DisplayFormatter
	pruneAllowed  func() bool
	now           func() time.Time
}

func NewService(opts ServiceOptions) *Service {
	if opts.DB == nil {
		opts.DB = func() *sql.DB { return nil }
	}
	if opts.Repository == nil {
		opts.Repository = NewSQLiteRepository(opts.DB)
	}
	if opts.Timezone == nil {
		opts.Timezone = func() (*time.Location, string) { return time.UTC, "UTC" }
	}
	if opts.FormatDisplay == nil {
		opts.FormatDisplay = formatTimestampForDisplay
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{
		repo:          opts.Repository,
		notify:        opts.Notify,
		timezone:      opts.Timezone,
		formatDisplay: opts.FormatDisplay,
		pruneAllowed:  opts.PruneAllowed,
		now:           opts.Now,
	}
}

func (s *Service) Write(evt Event) error {
	return s.repo.Write(evt)
}

func (s *Service) Record(actor, clientIP, action, targetType, targetName, status, message string, meta map[string]any) error {
	evt := Event{
		CreatedAt:  s.now().UTC().Format(time.RFC3339),
		Actor:      truncateString(actor, 128),
		Action:     truncateString(action, 64),
		TargetType: truncateString(targetType, 64),
		TargetName: truncateString(targetName, 255),
		Status:     truncateString(status, 32),
		Message:    truncateString(message, MessageMaxLen),
		MetaJSON:   SanitizeMeta(meta),
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

func (s *Service) List(filter ListFilter) (ListResult, error) {
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

	total, err := s.repo.Count(filter)
	if err != nil {
		return ListResult{}, &ListError{Stage: "count", Err: err}
	}

	items, err := s.repo.List(filter, pageSize, offset)
	if err != nil {
		return ListResult{}, err
	}
	loc, timezoneName := s.timezone()
	for i := range items {
		items[i].CreatedAtDisplay, _ = s.formatDisplay(items[i].CreatedAt, loc, timezoneName)
	}

	return ListResult{
		Items:    items,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	}, nil
}

func (s *Service) LoadByID(id string) (Event, error) {
	return s.repo.LoadByID(id)
}

func (s *Service) Prune(retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	if s.pruneAllowed != nil && !s.pruneAllowed() {
		return nil
	}
	cutoff := s.now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	return s.repo.PruneBefore(cutoff)
}

func (s *Service) BuildAuditMarkdownReport(evt Event) string {
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

func (s *Service) BuildJobMarkdownReport(job jobs.Record) string {
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

func SanitizeMeta(meta map[string]any) string {
	if meta == nil {
		return "{}"
	}
	redacted := make(map[string]any, len(meta))
	for k, v := range meta {
		key := strings.ToLower(strings.TrimSpace(k))
		isPrecheckField := strings.HasPrefix(key, "precheck")
		isPassField := key == "pass" || strings.HasPrefix(key, "pass_") || strings.HasSuffix(key, "_pass")
		if (isPassField || strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "token")) && !isPrecheckField {
			continue
		}
		if !isPrecheckField && (key == "api_key" ||
			key == "access_key" ||
			key == "secret_key" ||
			key == "private_key" ||
			key == "ssh_key" ||
			key == "key" ||
			strings.HasPrefix(key, "key_") ||
			strings.HasSuffix(key, "_key") ||
			strings.HasSuffix(key, "_secret")) {
			continue
		}
		redacted[k] = v
	}
	raw, err := json.Marshal(redacted)
	if err != nil {
		return "{}"
	}
	if len(raw) > MetaMaxLen {
		log.Printf("Warning: audit metadata truncated from %d bytes across %d fields", len(raw), len(redacted))
		truncated := map[string]any{
			"_truncated":      true,
			"original_length": len(raw),
			"fields":          len(redacted),
			"preview":         "",
		}
		previewRunes := []rune(string(raw))
		lo := 0
		hi := len(previewRunes)
		best := `{"_truncated":true}`
		for lo <= hi {
			mid := (lo + hi) / 2
			preview := string(previewRunes[:mid])
			if mid < len(previewRunes) {
				preview += "..."
			}
			truncated["preview"] = preview
			candidate, marshalErr := json.Marshal(truncated)
			if marshalErr != nil {
				hi = mid - 1
				continue
			}
			if len(candidate) <= MetaMaxLen {
				best = string(candidate)
				lo = mid + 1
				continue
			}
			hi = mid - 1
		}
		return best
	}
	return string(raw)
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

func truncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(strings.TrimSpace(s))
	if len(runes) <= maxLen {
		return string(runes)
	}
	return string(runes[:maxLen])
}

func formatTimestampForDisplay(raw string, loc *time.Location, timezoneName string) (string, string) {
	if loc == nil {
		loc = time.UTC
	}
	if strings.TrimSpace(timezoneName) == "" {
		timezoneName = "UTC"
	}
	parsed, err := parseTimestamp(raw)
	if err != nil {
		value := strings.TrimSpace(raw)
		if value == "" {
			return "-", timezoneName
		}
		return value, timezoneName
	}
	return parsed.In(loc).Format("2006-01-02 15:04:05 MST"), timezoneName
}

func parseTimestamp(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, fmt.Errorf("timestamp is required")
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		jobs.TimestampLayout,
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp format %q", value)
}
