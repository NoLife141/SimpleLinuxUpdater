package main

import (
	"database/sql"
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

func writeMarkdownDownload(c *gin.Context, filename string, body string) {
	c.Header("Content-Type", "text/markdown; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.String(http.StatusOK, body)
}

func loadAuditEventByID(id string) (AuditEvent, error) {
	return auditService.LoadByID(id)
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

func buildAuditMarkdownReport(evt AuditEvent) string {
	return auditService.BuildAuditMarkdownReport(evt)
}

func buildJobMarkdownReport(job JobRecord) string {
	return auditService.BuildJobMarkdownReport(job)
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
