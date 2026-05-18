package main

import (
	"database/sql"
	"log"
	"time"

	auditpkg "debian-updater/internal/audit"
)

type AuditEvent = auditpkg.Event
type AuditService = auditpkg.Service
type AuditListFilter = auditpkg.ListFilter
type AuditListResult = auditpkg.ListResult
type AuditListError = auditpkg.ListError

type auditDBProvider func() *sql.DB

type auditNotifier func(string)

type auditTimezoneProvider func() (*time.Location, string)

var auditService = NewAuditService(getDB, notifyDashboardEvent, currentAppTimezone)

func NewAuditService(db auditDBProvider, notify auditNotifier, timezone auditTimezoneProvider) *AuditService {
	if db == nil {
		db = getDB
	}
	if timezone == nil {
		timezone = currentAppTimezone
	}
	var notifier auditpkg.Notifier
	if notify != nil {
		notifier = func(reason string) { notify(reason) }
	}
	return auditpkg.NewService(auditpkg.ServiceOptions{
		DB:            func() *sql.DB { return db() },
		Notify:        notifier,
		Timezone:      func() (*time.Location, string) { return timezone() },
		FormatDisplay: formatTimestampForAppDisplayWithTimezone,
		PruneAllowed:  auditPruneAllowed,
	})
}

func auditPruneAllowed() bool {
	// Check maintenance before taking backupRestoreMu to avoid unnecessary lock
	// contention, then re-check after backupRestoreMu.RLock() because maintenance
	// can become active in the gap between the first currentMaintenanceState()
	// read and acquiring backupRestoreMu.
	if currentMaintenanceState().Active {
		return false
	}
	backupRestoreMu.RLock()
	defer backupRestoreMu.RUnlock()
	return !currentMaintenanceState().Active
}

func sanitizeAuditMeta(meta map[string]any) string {
	return auditpkg.SanitizeMeta(meta)
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
