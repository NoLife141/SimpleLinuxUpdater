package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestBuildObservabilitySummaryAggregates(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "observability.db"))
	_ = getDB()

	now := time.Date(2026, 2, 20, 15, 0, 0, 0, time.UTC)

	mustMeta := func(meta map[string]any) string {
		t.Helper()
		raw, err := json.Marshal(meta)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		return string(raw)
	}

	seed := []AuditEvent{
		{
			CreatedAt:  now.Add(-1 * time.Hour).Format(time.RFC3339),
			Action:     updateCompleteAction,
			Status:     "success",
			TargetType: "server",
			TargetName: "srv-a",
			Message:    "ok",
			MetaJSON:   mustMeta(map[string]any{"duration_ms": 1200}),
		},
		{
			CreatedAt:  now.Add(-2 * time.Hour).Format(time.RFC3339),
			Action:     updateCompleteAction,
			Status:     "failure",
			TargetType: "server",
			TargetName: "srv-b",
			Message:    "precheck fail",
			MetaJSON:   mustMeta(map[string]any{"precheck_failed": "apt_health", "duration_ms": 500}),
		},
		{
			CreatedAt:  now.Add(-3 * time.Hour).Format(time.RFC3339),
			Action:     updateCompleteAction,
			Status:     "failure",
			TargetType: "server",
			TargetName: "srv-c",
			Message:    "postcheck fail",
			MetaJSON:   mustMeta(map[string]any{"postcheck_failed": "failed_units"}),
		},
		{
			CreatedAt:  now.Add(-4 * time.Hour).Format(time.RFC3339),
			Action:     updateCompleteAction,
			Status:     "failure",
			TargetType: "server",
			TargetName: "srv-d",
			Message:    "retry exhausted",
			MetaJSON:   mustMeta(map[string]any{"retry_exhausted": true}),
		},
		{
			CreatedAt:  now.Add(-5 * time.Hour).Format(time.RFC3339),
			Action:     updateCompleteAction,
			Status:     "failure",
			TargetType: "server",
			TargetName: "srv-e",
			Message:    "transient",
			MetaJSON:   mustMeta(map[string]any{"last_error_class": "transient"}),
		},
		{
			CreatedAt:  now.Add(-6 * time.Hour).Format(time.RFC3339),
			Action:     updateCompleteAction,
			Status:     "failure",
			TargetType: "server",
			TargetName: "srv-f",
			Message:    "malformed meta",
			MetaJSON:   "{",
		},
		{
			CreatedAt:  now.Add(-90 * time.Minute).Format(time.RFC3339),
			Action:     updateCompleteAction,
			Status:     "ignored",
			TargetType: "server",
			TargetName: "srv-g",
			Message:    "ignored update",
			MetaJSON:   mustMeta(map[string]any{"duration_ms": 100}),
		},
		{
			CreatedAt:  now.Add(-9 * 24 * time.Hour).Format(time.RFC3339),
			Action:     updateCompleteAction,
			Status:     "success",
			TargetType: "server",
			TargetName: "srv-old",
			Message:    "outside window",
			MetaJSON:   mustMeta(map[string]any{"duration_ms": 999}),
		},
	}
	for _, evt := range seed {
		if err := writeAuditEvent(evt); err != nil {
			t.Fatalf("writeAuditEvent() error = %v", err)
		}
	}

	summary, err := buildObservabilitySummary("7d", now)
	if err != nil {
		t.Fatalf("buildObservabilitySummary() error = %v", err)
	}

	if summary.Totals.UpdatesTotal != 6 {
		t.Fatalf("UpdatesTotal = %d, want 6", summary.Totals.UpdatesTotal)
	}
	if summary.Totals.UpdatesSuccess != 1 {
		t.Fatalf("UpdatesSuccess = %d, want 1", summary.Totals.UpdatesSuccess)
	}
	if summary.Totals.UpdatesFailure != 5 {
		t.Fatalf("UpdatesFailure = %d, want 5", summary.Totals.UpdatesFailure)
	}
	if summary.Duration.SamplesWithDuration != 2 {
		t.Fatalf("SamplesWithDuration = %d, want 2", summary.Duration.SamplesWithDuration)
	}
	if summary.Duration.SamplesWithoutDuration != 4 {
		t.Fatalf("SamplesWithoutDuration = %d, want 4", summary.Duration.SamplesWithoutDuration)
	}
	if summary.Duration.AvgMS != 850 {
		t.Fatalf("AvgMS = %.2f, want 850", summary.Duration.AvgMS)
	}

	gotCauses := map[string]int{}
	for _, item := range summary.FailureCauses {
		gotCauses[item.Cause] = item.Count
	}
	wantCauses := map[string]int{
		"precheck:apt_health":    1,
		"postcheck:failed_units": 1,
		"retry_exhausted":        1,
		"error_class:transient":  1,
		"unknown":                1,
	}
	for cause, want := range wantCauses {
		if gotCauses[cause] != want {
			t.Fatalf("failure cause %q = %d, want %d (all=%v)", cause, gotCauses[cause], want, gotCauses)
		}
	}
}

func TestBuildObservabilitySummaryEmpty(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "observability-empty.db"))
	_ = getDB()

	summary, err := buildObservabilitySummary("7d", time.Now().UTC())
	if err != nil {
		t.Fatalf("buildObservabilitySummary() error = %v", err)
	}

	if summary.Totals.UpdatesTotal != 0 {
		t.Fatalf("UpdatesTotal = %d, want 0", summary.Totals.UpdatesTotal)
	}
	if summary.Totals.SuccessRatePct != 0 {
		t.Fatalf("SuccessRatePct = %.2f, want 0", summary.Totals.SuccessRatePct)
	}
	if summary.Duration.AvgMS != 0 {
		t.Fatalf("AvgMS = %.2f, want 0", summary.Duration.AvgMS)
	}
	if summary.FailureCauses == nil {
		t.Fatalf("FailureCauses is nil, want empty non-nil slice")
	}
	if len(summary.FailureCauses) != 0 {
		t.Fatalf("len(FailureCauses) = %d, want 0", len(summary.FailureCauses))
	}
}

func TestHandleObservabilitySummaryInvalidWindow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/observability/summary", handleObservabilitySummary)

	req := httptest.NewRequest(http.MethodGet, "/api/observability/summary?window=1h", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleMetricsIncludesExpectedSeries(t *testing.T) {
	preserveDBState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", filepath.Join(t.TempDir(), "metrics.db"))
	_ = getDB()

	metaJSON, err := json.Marshal(map[string]any{
		"duration_ms":      1234,
		"precheck_failed":  "disk_space",
		"retry_exhausted":  true,
		"last_error_class": "transient",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := writeAuditEvent(AuditEvent{
		CreatedAt:  time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339),
		Action:     updateCompleteAction,
		Status:     "failure",
		TargetType: "server",
		TargetName: "srv-metrics",
		Message:    "failed",
		MetaJSON:   string(metaJSON),
	}); err != nil {
		t.Fatalf("writeAuditEvent() error = %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", handleMetrics)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ctype := rec.Header().Get("Content-Type"); !strings.Contains(ctype, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain", ctype)
	}
	body := rec.Body.String()
	for _, expected := range []string{
		"simplelinuxupdater_update_runs_total",
		"simplelinuxupdater_update_success_rate_percent",
		"simplelinuxupdater_update_duration_avg_milliseconds",
		"simplelinuxupdater_update_duration_samples_total",
		"simplelinuxupdater_update_failures_by_cause_total",
	} {
		expected := expected
		t.Run(expected, func(t *testing.T) {
			if !strings.Contains(body, expected) {
				t.Fatalf("metrics body missing %q", expected)
			}
		})
	}
}
