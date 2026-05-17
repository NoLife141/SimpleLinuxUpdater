package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func markdownReportFilename(prefix, id string) string {
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, strings.TrimSpace(id))
	if clean == "" {
		clean = "report"
	}
	return fmt.Sprintf("%s-%s.md", prefix, clean)
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

func writeMarkdownDownload(c *gin.Context, filename string, body string) {
	c.Header("Content-Type", "text/markdown; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.String(http.StatusOK, body)
}

func loadAuditEventByID(id string) (AuditEvent, error) {
	var evt AuditEvent
	err := getDB().QueryRow(`
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

func buildAuditMarkdownReport(evt AuditEvent) string {
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

func handleAuditReport(c *gin.Context) {
	evt, err := loadAuditEventByID(c.Param("id"))
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "audit event not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load audit event"})
		return
	}
	writeMarkdownDownload(c, markdownReportFilename("audit", fmt.Sprintf("%d", evt.ID)), buildAuditMarkdownReport(evt))
}

func buildJobMarkdownReport(job JobRecord) string {
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

func handleJobReport(c *gin.Context) {
	jm := currentJobManager()
	if jm == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "job manager unavailable"})
		return
	}
	job, err := jm.GetJob(c.Param("id"))
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load job"})
		return
	}
	writeMarkdownDownload(c, markdownReportFilename("job", job.ID), buildJobMarkdownReport(job))
}
