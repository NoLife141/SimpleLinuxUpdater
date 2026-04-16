package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func prepareUpdatePolicyTestState(t *testing.T, dbFile string) {
	t.Helper()
	preserveDBState(t)
	preserveServerState(t)
	preserveSessionState(t)
	preserveRateLimiterState(t)
	preserveMetricsTokenState(t)
	t.Setenv("DEBIAN_UPDATER_DB_PATH", dbFile)
	if err := initializeJobManager(); err != nil {
		t.Fatalf("initializeJobManager() unexpected error: %v", err)
	}
}

func TestUpdatePolicyAPIValidationAndCRUD(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-api.db")
	prepareUpdatePolicyTestState(t, dbFile)

	server := Server{Name: "srv-policy-api", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Tags: []string{"prod"}, Upgradable: []string{}},
	}
	mu.Unlock()

	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	invalidBody := bytes.NewBufferString(`{
		"name":"Weekly invalid",
		"enabled":true,
		"target_tag":"prod",
		"package_scope":"security",
		"execution_mode":"scan_only",
		"cadence_kind":"weekly",
		"time_local":"01:00",
		"weekdays":[]
	}`)
	invalidRec := httptest.NewRecorder()
	invalidReq := httptest.NewRequest(http.MethodPost, "/api/update-policies", invalidBody)
	invalidReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(invalidReq)
	invalidReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(invalidRec, invalidReq)
	if invalidRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid create status = %d, want %d (body=%s)", invalidRec.Code, http.StatusBadRequest, invalidRec.Body.String())
	}

	createBody := bytes.NewBufferString(`{
		"name":"Nightly security",
		"enabled":true,
		"target_tag":"prod",
		"package_scope":"security",
		"execution_mode":"approval_required",
		"cadence_kind":"daily",
		"time_local":"02:15",
		"weekdays":[],
		"approval_timeout_minutes":720,
		"policy_blackouts":[{"weekdays":["sun"],"start_time":"01:00","end_time":"04:00"}]
	}`)
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/api/update-policies", createBody)
	createReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(createReq)
	createReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d (body=%s)", createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	var created UpdatePolicy
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created policy: %v", err)
	}
	if created.ID <= 0 || created.Name != "Nightly security" {
		t.Fatalf("created policy = %+v, want persisted record", created)
	}

	listRec := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/update-policies", nil)
	listReq.AddCookie(sessionCookie)
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	var listResp struct {
		Items    []UpdatePolicy `json:"items"`
		Timezone string         `json:"timezone"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal policy list: %v", err)
	}
	if len(listResp.Items) != 1 {
		t.Fatalf("policy count = %d, want 1", len(listResp.Items))
	}
	if len(listResp.Items[0].MatchedServers) != 1 || listResp.Items[0].MatchedServers[0] != server.Name {
		t.Fatalf("matched servers = %+v, want [%q]", listResp.Items[0].MatchedServers, server.Name)
	}
	if strings.TrimSpace(listResp.Timezone) == "" {
		t.Fatalf("timezone missing from list response")
	}

	updateBody := bytes.NewBufferString(`{
		"name":"Weekly full",
		"enabled":false,
		"target_tag":"prod",
		"package_scope":"full",
		"execution_mode":"scan_only",
		"cadence_kind":"weekly",
		"time_local":"03:30",
		"weekdays":["mon","thu"],
		"approval_timeout_minutes":0,
		"policy_blackouts":[]
	}`)
	updateRec := httptest.NewRecorder()
	updateReq := httptest.NewRequest(http.MethodPut, "/api/update-policies/"+strconvFormatInt(created.ID), updateBody)
	updateReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(updateReq)
	updateReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update status = %d, want %d (body=%s)", updateRec.Code, http.StatusOK, updateRec.Body.String())
	}

	settingsBody := bytes.NewBufferString(`{
		"global_blackouts":[{"weekdays":["sat"],"start_time":"00:00","end_time":"06:00"}]
	}`)
	settingsRec := httptest.NewRecorder()
	settingsReq := httptest.NewRequest(http.MethodPut, "/api/update-policies/settings", settingsBody)
	settingsReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(settingsReq)
	settingsReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(settingsRec, settingsReq)
	if settingsRec.Code != http.StatusOK {
		t.Fatalf("settings update status = %d, want %d (body=%s)", settingsRec.Code, http.StatusOK, settingsRec.Body.String())
	}

	overrideBody := bytes.NewBufferString(`{"disabled":true}`)
	overrideRec := httptest.NewRecorder()
	overrideReq := httptest.NewRequest(http.MethodPut, "/api/update-policies/"+strconvFormatInt(created.ID)+"/overrides/"+server.Name, overrideBody)
	overrideReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(overrideReq)
	overrideReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(overrideRec, overrideReq)
	if overrideRec.Code != http.StatusOK {
		t.Fatalf("override update status = %d, want %d (body=%s)", overrideRec.Code, http.StatusOK, overrideRec.Body.String())
	}

	renameBody := bytes.NewBufferString(`{
		"name":"srv-policy-api-renamed",
		"host":"example.org",
		"port":22,
		"user":"root",
		"pass":"",
		"tags":["prod"]
	}`)
	renameRec := httptest.NewRecorder()
	renameReq := httptest.NewRequest(http.MethodPut, "/api/servers/"+server.Name, renameBody)
	renameReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(renameReq)
	renameReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(renameRec, renameReq)
	if renameRec.Code != http.StatusOK {
		t.Fatalf("rename status = %d, want %d (body=%s)", renameRec.Code, http.StatusOK, renameRec.Body.String())
	}

	overridesRec := httptest.NewRecorder()
	overridesReq := httptest.NewRequest(http.MethodGet, "/api/update-policies/"+strconvFormatInt(created.ID)+"/overrides", nil)
	overridesReq.AddCookie(sessionCookie)
	handler.ServeHTTP(overridesRec, overridesReq)
	if overridesRec.Code != http.StatusOK {
		t.Fatalf("overrides list status = %d, want %d (body=%s)", overridesRec.Code, http.StatusOK, overridesRec.Body.String())
	}
	var overridesResp struct {
		Items []UpdatePolicyOverride `json:"items"`
	}
	if err := json.Unmarshal(overridesRec.Body.Bytes(), &overridesResp); err != nil {
		t.Fatalf("unmarshal overrides response: %v", err)
	}
	if len(overridesResp.Items) != 1 {
		t.Fatalf("override item count = %d, want 1", len(overridesResp.Items))
	}
	if overridesResp.Items[0].ServerName != "srv-policy-api-renamed" || !overridesResp.Items[0].Disabled {
		t.Fatalf("override after rename = %+v, want server_name=srv-policy-api-renamed disabled=true", overridesResp.Items[0])
	}

	postRenameListRec := httptest.NewRecorder()
	postRenameListReq := httptest.NewRequest(http.MethodGet, "/api/update-policies", nil)
	postRenameListReq.AddCookie(sessionCookie)
	handler.ServeHTTP(postRenameListRec, postRenameListReq)
	if postRenameListRec.Code != http.StatusOK {
		t.Fatalf("post-rename list status = %d, want %d", postRenameListRec.Code, http.StatusOK)
	}
	var postRenameListResp struct {
		Items []UpdatePolicy `json:"items"`
	}
	if err := json.Unmarshal(postRenameListRec.Body.Bytes(), &postRenameListResp); err != nil {
		t.Fatalf("unmarshal post-rename policy list: %v", err)
	}
	if len(postRenameListResp.Items) != 1 {
		t.Fatalf("post-rename policy count = %d, want 1", len(postRenameListResp.Items))
	}
	if len(postRenameListResp.Items[0].MatchedServers) != 0 {
		t.Fatalf("matched servers after rename = %+v, want [] due to persisted override", postRenameListResp.Items[0].MatchedServers)
	}

	deleteRec := httptest.NewRecorder()
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/servers/srv-policy-api-renamed", nil)
	deleteReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(deleteReq)
	handler.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want %d (body=%s)", deleteRec.Code, http.StatusOK, deleteRec.Body.String())
	}

	postDeleteOverridesRec := httptest.NewRecorder()
	postDeleteOverridesReq := httptest.NewRequest(http.MethodGet, "/api/update-policies/"+strconvFormatInt(created.ID)+"/overrides", nil)
	postDeleteOverridesReq.AddCookie(sessionCookie)
	handler.ServeHTTP(postDeleteOverridesRec, postDeleteOverridesReq)
	if postDeleteOverridesRec.Code != http.StatusOK {
		t.Fatalf("post-delete overrides status = %d, want %d (body=%s)", postDeleteOverridesRec.Code, http.StatusOK, postDeleteOverridesRec.Body.String())
	}
	var postDeleteOverridesResp struct {
		Items []UpdatePolicyOverride `json:"items"`
	}
	if err := json.Unmarshal(postDeleteOverridesRec.Body.Bytes(), &postDeleteOverridesResp); err != nil {
		t.Fatalf("unmarshal post-delete overrides response: %v", err)
	}
	if len(postDeleteOverridesResp.Items) != 0 {
		t.Fatalf("override items after server delete = %d, want 0", len(postDeleteOverridesResp.Items))
	}
}

func TestAppTimezoneAPIAndScheduledSettingsMirror(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "app-timezone-api.db")
	prepareUpdatePolicyTestState(t, dbFile)

	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)

	getRec := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/api/app-settings/timezone", nil)
	getReq.AddCookie(sessionCookie)
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get timezone status = %d, want %d (body=%s)", getRec.Code, http.StatusOK, getRec.Body.String())
	}
	var initial AppTimezoneResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &initial); err != nil {
		t.Fatalf("unmarshal initial timezone response: %v", err)
	}
	if strings.TrimSpace(initial.Timezone) == "" {
		t.Fatalf("initial timezone missing from response")
	}

	putRec := httptest.NewRecorder()
	putReq := httptest.NewRequest(http.MethodPut, "/api/app-settings/timezone", bytes.NewBufferString(`{"timezone":"America/Toronto"}`))
	putReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(putReq)
	putReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put timezone status = %d, want %d (body=%s)", putRec.Code, http.StatusOK, putRec.Body.String())
	}
	var saved AppTimezoneResponse
	if err := json.Unmarshal(putRec.Body.Bytes(), &saved); err != nil {
		t.Fatalf("unmarshal saved timezone response: %v", err)
	}
	if saved.Timezone != "America/Toronto" {
		t.Fatalf("saved timezone = %q, want %q", saved.Timezone, "America/Toronto")
	}
	if saved.ResolvedTimezone != "America/Toronto" {
		t.Fatalf("saved resolved timezone = %q, want %q", saved.ResolvedTimezone, "America/Toronto")
	}

	settingsRec := httptest.NewRecorder()
	settingsReq := httptest.NewRequest(http.MethodGet, "/api/update-policies/settings", nil)
	settingsReq.AddCookie(sessionCookie)
	handler.ServeHTTP(settingsRec, settingsReq)
	if settingsRec.Code != http.StatusOK {
		t.Fatalf("scheduled settings status = %d, want %d (body=%s)", settingsRec.Code, http.StatusOK, settingsRec.Body.String())
	}
	var settingsResp UpdatePolicySettingsResponse
	if err := json.Unmarshal(settingsRec.Body.Bytes(), &settingsResp); err != nil {
		t.Fatalf("unmarshal scheduled settings response: %v", err)
	}
	if settingsResp.Timezone != "America/Toronto" {
		t.Fatalf("scheduled settings timezone = %q, want %q", settingsResp.Timezone, "America/Toronto")
	}
	if settingsResp.ResolvedTimezone != "America/Toronto" {
		t.Fatalf("scheduled settings resolved timezone = %q, want %q", settingsResp.ResolvedTimezone, "America/Toronto")
	}

	invalidRec := httptest.NewRecorder()
	invalidReq := httptest.NewRequest(http.MethodPut, "/api/app-settings/timezone", bytes.NewBufferString(`{"timezone":"Mars/Olympus"}`))
	invalidReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(invalidReq)
	invalidReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(invalidRec, invalidReq)
	if invalidRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid timezone status = %d, want %d (body=%s)", invalidRec.Code, http.StatusBadRequest, invalidRec.Body.String())
	}
}

func TestSaveAppTimezoneLocalResolvesSystemTimezoneName(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "app-timezone-local-save.db")
	prepareUpdatePolicyTestState(t, dbFile)

	origDetect := detectSystemTimezoneNameFunc
	detectSystemTimezoneNameFunc = func() (string, error) {
		return "Europe/London", nil
	}
	t.Cleanup(func() {
		detectSystemTimezoneNameFunc = origDetect
	})

	name, err := saveAppTimezone("Local")
	if err != nil {
		t.Fatalf("saveAppTimezone(Local) unexpected error: %v", err)
	}
	if name != "Europe/London" {
		t.Fatalf("saveAppTimezone(Local) = %q, want %q", name, "Europe/London")
	}
	if got := currentAppTimezoneName(); got != "Europe/London" {
		t.Fatalf("currentAppTimezoneName() = %q, want %q", got, "Europe/London")
	}
}

func TestDefaultAppTimezoneNameFallbackDoesNotExposeLocal(t *testing.T) {
	origDetect := detectSystemTimezoneNameFunc
	detectSystemTimezoneNameFunc = func() (string, error) {
		return "", os.ErrNotExist
	}
	oldLocal := time.Local
	time.Local = time.FixedZone("XST", 2*60*60)
	t.Cleanup(func() {
		detectSystemTimezoneNameFunc = origDetect
		time.Local = oldLocal
	})

	if got := defaultAppTimezoneName(); got != "+02:00" {
		t.Fatalf("defaultAppTimezoneName() = %q, want %q", got, "+02:00")
	}
}

func TestLoadCurrentAppTimezoneFallbackKeepsLocationAndNameAligned(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "app-timezone-fallback-aligned.db")
	prepareUpdatePolicyTestState(t, dbFile)

	origDetect := detectSystemTimezoneNameFunc
	detectSystemTimezoneNameFunc = func() (string, error) {
		return "", os.ErrNotExist
	}
	oldLocal := time.Local
	time.Local = time.FixedZone("XST", 2*60*60)
	t.Cleanup(func() {
		detectSystemTimezoneNameFunc = origDetect
		time.Local = oldLocal
	})

	loc, name, err := loadCurrentAppTimezone()
	if err != nil {
		t.Fatalf("loadCurrentAppTimezone() unexpected error: %v", err)
	}
	if loc == nil || loc.String() != "XST" {
		t.Fatalf("loadCurrentAppTimezone() location = %v, want XST", loc)
	}
	if name != "+02:00" {
		t.Fatalf("loadCurrentAppTimezone() name = %q, want %q", name, "+02:00")
	}
}

func TestDetectSystemTimezoneNamePrefersLocaltimeOverMetadata(t *testing.T) {
	t.Setenv("TZ", "")
	oldLocal := time.Local
	time.Local = time.FixedZone("Local", 0)
	t.Cleanup(func() {
		time.Local = oldLocal
	})

	tempDir := t.TempDir()
	zoneinfoRoot := filepath.Join(tempDir, "zoneinfo")
	if err := os.MkdirAll(filepath.Join(zoneinfoRoot, "America"), 0o755); err != nil {
		t.Fatalf("mkdir zoneinfo root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(zoneinfoRoot, "America", "Toronto"), []byte("toronto-zone"), 0o644); err != nil {
		t.Fatalf("write zoneinfo file: %v", err)
	}
	localtimePath := filepath.Join(tempDir, "localtime")
	if err := os.WriteFile(localtimePath, []byte("toronto-zone"), 0o644); err != nil {
		t.Fatalf("write localtime file: %v", err)
	}
	metadataPath := filepath.Join(tempDir, "timezone")
	if err := os.WriteFile(metadataPath, []byte("UTC"), 0o644); err != nil {
		t.Fatalf("write metadata timezone file: %v", err)
	}

	origLocaltimePath := appTimezoneLocaltimePath
	origMetadataPaths := appTimezoneMetadataPaths
	origZoneinfoRoots := appTimezoneZoneinfoRoots
	t.Cleanup(func() {
		appTimezoneLocaltimePath = origLocaltimePath
		appTimezoneMetadataPaths = origMetadataPaths
		appTimezoneZoneinfoRoots = origZoneinfoRoots
	})

	appTimezoneLocaltimePath = localtimePath
	appTimezoneMetadataPaths = []string{metadataPath}
	appTimezoneZoneinfoRoots = []string{zoneinfoRoot}

	name, err := detectSystemTimezoneName()
	if err != nil {
		t.Fatalf("detectSystemTimezoneName() unexpected error: %v", err)
	}
	if name != "America/Toronto" {
		t.Fatalf("detectSystemTimezoneName() = %q, want %q", name, "America/Toronto")
	}
}

func TestSaveAppTimezoneRejectsBrowserUnsafeAlias(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "app-timezone-invalid-alias.db")
	prepareUpdatePolicyTestState(t, dbFile)

	_, err := saveAppTimezone("Factory")
	if err == nil {
		t.Fatalf("saveAppTimezone(Factory) expected error, got nil")
	}
	if !isAppTimezoneValidationError(err) {
		t.Fatalf("saveAppTimezone(Factory) error = %v, want app timezone validation error", err)
	}
}

func TestSaveAppTimezoneRejectsBrowserUnsafeShortName(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "app-timezone-short-name.db")
	prepareUpdatePolicyTestState(t, dbFile)

	_, err := saveAppTimezone("EST")
	if err == nil {
		t.Fatalf("saveAppTimezone(EST) expected error, got nil")
	}
	if !isAppTimezoneValidationError(err) {
		t.Fatalf("saveAppTimezone(EST) error = %v, want app timezone validation error", err)
	}
}

func TestSaveAppTimezoneRejectsOffsetLabel(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "app-timezone-offset-name.db")
	prepareUpdatePolicyTestState(t, dbFile)

	_, err := saveAppTimezone("+02:00")
	if err == nil {
		t.Fatalf("saveAppTimezone(+02:00) expected error, got nil")
	}
	if !isAppTimezoneValidationError(err) {
		t.Fatalf("saveAppTimezone(+02:00) error = %v, want app timezone validation error", err)
	}
}

func TestSaveAppTimezoneLocalFallsBackWhenNameUnresolved(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "app-timezone-local-fallback.db")
	prepareUpdatePolicyTestState(t, dbFile)

	origDetect := detectSystemTimezoneNameFunc
	detectSystemTimezoneNameFunc = func() (string, error) {
		return "", os.ErrNotExist
	}
	oldLocal := time.Local
	time.Local = time.FixedZone("XST", 2*60*60)
	t.Cleanup(func() {
		detectSystemTimezoneNameFunc = origDetect
		time.Local = oldLocal
	})

	name, err := saveAppTimezone("Local")
	if err != nil {
		t.Fatalf("saveAppTimezone(Local) unexpected error: %v", err)
	}
	if name != "+02:00" {
		t.Fatalf("saveAppTimezone(Local) = %q, want %q", name, "+02:00")
	}
	loc, currentName := currentAppTimezone()
	if currentName != "+02:00" {
		t.Fatalf("currentAppTimezone() name = %q, want %q", currentName, "+02:00")
	}
	if loc == nil || loc.String() != "XST" {
		t.Fatalf("currentAppTimezone() location = %v, want XST", loc)
	}
}

func TestAppTimezoneDisplayAndResolvedForLocalUsesFriendlyLabel(t *testing.T) {
	display, resolved := appTimezoneDisplayAndResolved(time.FixedZone("XST", 2*60*60), "Local", time.Now())
	if display != appTimezoneLocalDisplayLabel {
		t.Fatalf("appTimezoneDisplayAndResolved() display = %q, want %q", display, appTimezoneLocalDisplayLabel)
	}
	if resolved != "" {
		t.Fatalf("appTimezoneDisplayAndResolved() resolved = %q, want empty", resolved)
	}
}

func TestCurrentAppTimezoneResolvesLegacyLocalSetting(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "app-timezone-legacy-local.db")
	prepareUpdatePolicyTestState(t, dbFile)

	if err := upsertSettingValue(appTimezoneSetting, "Local"); err != nil {
		t.Fatalf("upsertSettingValue(Local) unexpected error: %v", err)
	}

	origDetect := detectSystemTimezoneNameFunc
	detectSystemTimezoneNameFunc = func() (string, error) {
		return "Europe/London", nil
	}
	t.Cleanup(func() {
		detectSystemTimezoneNameFunc = origDetect
	})

	loc, name, err := loadCurrentAppTimezone()
	if err != nil {
		t.Fatalf("loadCurrentAppTimezone() unexpected error: %v", err)
	}
	if loc == nil || loc.String() != "Europe/London" {
		t.Fatalf("loadCurrentAppTimezone() location = %v, want Europe/London", loc)
	}
	if name != "Europe/London" {
		t.Fatalf("loadCurrentAppTimezone() name = %q, want %q", name, "Europe/London")
	}
}

func TestSetUpdatePolicyOverrideFalseRemovesPersistedOptOut(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-override-clear.db")
	prepareUpdatePolicyTestState(t, dbFile)

	policy, err := createUpdatePolicy(UpdatePolicy{
		Name:          "Nightly prod",
		Enabled:       true,
		TargetTag:     "prod",
		PackageScope:  updatePolicyPackageScopeSecurity,
		ExecutionMode: updatePolicyExecutionScanOnly,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     "02:00",
	})
	if err != nil {
		t.Fatalf("createUpdatePolicy() unexpected error: %v", err)
	}

	created, err := setUpdatePolicyOverride(policy.ID, "srv-override", true)
	if err != nil {
		t.Fatalf("setUpdatePolicyOverride(true) unexpected error: %v", err)
	}
	if !created.Disabled {
		t.Fatalf("created override = %+v, want disabled=true", created)
	}

	cleared, err := setUpdatePolicyOverride(policy.ID, "srv-override", false)
	if err != nil {
		t.Fatalf("setUpdatePolicyOverride(false) unexpected error: %v", err)
	}
	if cleared.Disabled {
		t.Fatalf("cleared override = %+v, want disabled=false", cleared)
	}

	items, err := listUpdatePolicyOverrides(policy.ID)
	if err != nil {
		t.Fatalf("listUpdatePolicyOverrides() unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("override items = %+v, want none after clearing", items)
	}

	overrides, err := loadAllUpdatePolicyOverrides()
	if err != nil {
		t.Fatalf("loadAllUpdatePolicyOverrides() unexpected error: %v", err)
	}
	if perPolicy := overrides[policy.ID]; perPolicy != nil {
		if disabled, exists := perPolicy["srv-override"]; exists {
			t.Fatalf("override state persisted as %t, want row removed", disabled)
		}
	}
}

func TestUpdatePolicyOverrideRejectsUnknownServer(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-override-unknown-server.db")
	prepareUpdatePolicyTestState(t, dbFile)

	server := Server{Name: "srv-known", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Tags: []string{"prod"}, Upgradable: []string{}},
	}
	mu.Unlock()

	policy, err := createUpdatePolicy(UpdatePolicy{
		Name:          "Known server only",
		Enabled:       true,
		TargetTag:     "prod",
		PackageScope:  updatePolicyPackageScopeSecurity,
		ExecutionMode: updatePolicyExecutionScanOnly,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     "02:00",
	})
	if err != nil {
		t.Fatalf("createUpdatePolicy() unexpected error: %v", err)
	}

	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/update-policies/"+strconvFormatInt(policy.ID)+"/overrides/srv-missing", bytes.NewBufferString(`{"disabled":true}`))
	req.AddCookie(sessionCookie)
	markSameOriginAuthRequest(req)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown server override status = %d, want %d (body=%s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}

	items, err := listUpdatePolicyOverrides(policy.ID)
	if err != nil {
		t.Fatalf("listUpdatePolicyOverrides() unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("override items = %+v, want none for unknown server request", items)
	}
}

func TestCanonicalScheduledForUTCUsesFirstFallbackOccurrence(t *testing.T) {
	oldLocal := time.Local
	loc, err := time.LoadLocation("America/Toronto")
	if err != nil {
		t.Fatalf("LoadLocation() unexpected error: %v", err)
	}
	time.Local = loc
	t.Cleanup(func() {
		time.Local = oldLocal
	})

	firstOccurrence := time.Date(2026, time.November, 1, 1, 30, 0, 0, loc)
	secondParsed, err := time.Parse("2006-01-02 15:04 -0700 MST", "2026-11-01 01:30 -0500 EST")
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	secondOccurrence := secondParsed.In(loc)

	want := firstOccurrence.UTC().Format(jobTimestampLayout)
	if got := canonicalScheduledForUTC(firstOccurrence); got != want {
		t.Fatalf("canonicalScheduledForUTC(first) = %q, want %q", got, want)
	}
	if got := canonicalScheduledForUTC(secondOccurrence); got != want {
		t.Fatalf("canonicalScheduledForUTC(second) = %q, want %q", got, want)
	}
}

func TestProcessDueUpdatePoliciesUsesConfiguredAppTimezone(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-configured-timezone.db")
	prepareUpdatePolicyTestState(t, dbFile)

	t.Setenv(retryMaxAttemptsEnv, "1")
	t.Setenv(postchecksEnabledEnv, "false")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)

	oldLocal := time.Local
	time.Local = time.UTC
	t.Cleanup(func() {
		time.Local = oldLocal
	})

	if _, err := saveAppTimezone("America/Toronto"); err != nil {
		t.Fatalf("saveAppTimezone() unexpected error: %v", err)
	}

	now := time.Date(2026, time.January, 15, 7, 5, 0, 0, time.UTC)
	server := Server{Name: "srv-configured-timezone", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Tags: []string{"prod"}, Upgradable: []string{}},
	}
	mu.Unlock()

	policy, err := createUpdatePolicy(UpdatePolicy{
		Name:          "Configured timezone scan",
		Enabled:       true,
		TargetTag:     "prod",
		PackageScope:  updatePolicyPackageScopeSecurity,
		ExecutionMode: updatePolicyExecutionScanOnly,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     "02:05",
	})
	if err != nil {
		t.Fatalf("createUpdatePolicy() unexpected error: %v", err)
	}

	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd:               {stdout: "2048000\n2097152\n"},
			precheckLocksCmd:                   {err: fakeExitStatusError{code: 1, msg: "no process found"}},
			precheckDpkgAuditCmd:               {},
			precheckAptCheckCmd:                {},
			aptUpdateCmd:                       {},
			aptListUpgradableCmd:               {stdout: "Inst openssl [3.0.0-1] (3.0.1-1 Debian-Security:12/stable-security [amd64])\n"},
			buildPackageCVEQueryCmd("openssl"): {stdout: "CVE-2026-1001\n"},
		},
	}
	origDial := getDialSSHConnection()
	setDialSSHConnection(func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		return conn, nil
	})
	t.Cleanup(func() { setDialSSHConnection(origDial) })

	if err := processDueUpdatePolicies(now); err != nil {
		t.Fatalf("processDueUpdatePolicies() unexpected error: %v", err)
	}

	waitForCondition(t, 10*time.Second, func() bool {
		runs, err := listUpdatePolicyRuns(10)
		if err != nil {
			return false
		}
		for _, run := range runs {
			if run.PolicyID == policy.ID && run.ServerName == server.Name && run.Status == updatePolicyRunSucceeded {
				return true
			}
		}
		return false
	}, "configured-timezone run to complete")

	runs, err := listUpdatePolicyRuns(10)
	if err != nil {
		t.Fatalf("listUpdatePolicyRuns() unexpected error: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("run count = %d, want 1", len(runs))
	}
	if runs[0].ScheduledForUTC != now.Format(jobTimestampLayout) {
		t.Fatalf("scheduled_for_utc = %q, want %q", runs[0].ScheduledForUTC, now.Format(jobTimestampLayout))
	}
}

func TestAppTimezoneChangeKeepsPolicyWallClockMeaning(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-timezone-wallclock.db")
	prepareUpdatePolicyTestState(t, dbFile)

	policy := UpdatePolicy{
		CadenceKind: updatePolicyCadenceDaily,
		TimeLocal:   "02:00",
	}

	if _, err := saveAppTimezone("America/Toronto"); err != nil {
		t.Fatalf("saveAppTimezone(Toronto) unexpected error: %v", err)
	}
	torontoSlot := time.Date(2026, time.January, 15, 2, 0, 0, 0, currentAppLocation())
	if !policyDueAt(policy, torontoSlot) {
		t.Fatalf("policyDueAt(Toronto slot) = false, want true")
	}
	wantToronto := time.Date(2026, time.January, 15, 7, 0, 0, 0, time.UTC).Format(jobTimestampLayout)
	if got := canonicalScheduledForUTC(torontoSlot); got != wantToronto {
		t.Fatalf("canonicalScheduledForUTC(Toronto slot) = %q, want %q", got, wantToronto)
	}

	if _, err := saveAppTimezone("UTC"); err != nil {
		t.Fatalf("saveAppTimezone(UTC) unexpected error: %v", err)
	}
	utcSlot := time.Date(2026, time.January, 16, 2, 0, 0, 0, currentAppLocation())
	if !policyDueAt(policy, utcSlot) {
		t.Fatalf("policyDueAt(UTC slot) = false, want true")
	}
	wantUTC := time.Date(2026, time.January, 16, 2, 0, 0, 0, time.UTC).Format(jobTimestampLayout)
	if got := canonicalScheduledForUTC(utcSlot); got != wantUTC {
		t.Fatalf("canonicalScheduledForUTC(UTC slot) = %q, want %q", got, wantUTC)
	}
}

func TestProcessDueUpdatePoliciesDedupesAndHandlesSkips(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-scheduler.db")
	prepareUpdatePolicyTestState(t, dbFile)

	t.Setenv(retryMaxAttemptsEnv, "1")
	t.Setenv(postchecksEnabledEnv, "false")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)

	now := time.Now().In(time.Local).Truncate(time.Minute)
	timeLocal := now.Format("15:04")

	alpha := Server{Name: "alpha", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	beta := Server{Name: "beta", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	gamma := Server{Name: "gamma", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"nightly"}}
	mu.Lock()
	servers = []Server{alpha, beta, gamma}
	statusMap = map[string]*ServerStatus{
		alpha.Name: {Name: alpha.Name, Status: "idle", Tags: []string{"prod"}, Upgradable: []string{}},
		beta.Name:  {Name: beta.Name, Status: "updating", Tags: []string{"prod"}, Upgradable: []string{}},
		gamma.Name: {Name: gamma.Name, Status: "idle", Tags: []string{"nightly"}, Upgradable: []string{}},
	}
	mu.Unlock()

	autoApplyPolicy, err := createUpdatePolicy(UpdatePolicy{
		Name:            "Prod auto apply",
		Enabled:         true,
		TargetTag:       "prod",
		PackageScope:    "full",
		ExecutionMode:   updatePolicyExecutionAutoApply,
		CadenceKind:     updatePolicyCadenceDaily,
		TimeLocal:       timeLocal,
		PolicyBlackouts: []UpdatePolicyBlackoutWindow{},
	})
	if err != nil {
		t.Fatalf("create auto apply policy: %v", err)
	}
	if _, err := createUpdatePolicy(UpdatePolicy{
		Name:            "Prod scan only",
		Enabled:         true,
		TargetTag:       "prod",
		PackageScope:    "security",
		ExecutionMode:   updatePolicyExecutionScanOnly,
		CadenceKind:     updatePolicyCadenceDaily,
		TimeLocal:       timeLocal,
		PolicyBlackouts: []UpdatePolicyBlackoutWindow{},
	}); err != nil {
		t.Fatalf("create scan-only policy: %v", err)
	}
	if _, err := createUpdatePolicy(UpdatePolicy{
		Name:          "Nightly blackout",
		Enabled:       true,
		TargetTag:     "nightly",
		PackageScope:  "security",
		ExecutionMode: updatePolicyExecutionScanOnly,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     timeLocal,
		PolicyBlackouts: []UpdatePolicyBlackoutWindow{
			{Weekdays: []string{strings.ToLower(now.Weekday().String()[:3])}, StartTime: now.Format("15:04"), EndTime: now.Add(30 * time.Minute).Format("15:04")},
		},
	}); err != nil {
		t.Fatalf("create blackout policy: %v", err)
	}

	updateConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "2048000\n2097152\n"},
			precheckLocksCmd:     {err: fakeExitStatusError{code: 1, msg: "no process found"}},
			precheckDpkgAuditCmd: {},
			precheckAptCheckCmd:  {},
			aptUpdateCmd:         {},
			aptListUpgradableCmd: {stdout: "Inst openssl [3.0.0-1] (3.0.1-1 Debian-Security:12/stable-security [amd64])\n"},
			aptUpgradeCmd:        {},
		},
	}
	origDial := getDialSSHConnection()
	var dialCalls int32
	setDialSSHConnection(func(server Server, _ *ssh.ClientConfig) (sshConnection, error) {
		atomic.AddInt32(&dialCalls, 1)
		if server.Name != alpha.Name {
			t.Fatalf("unexpected dial for server %q", server.Name)
		}
		return updateConn, nil
	})
	t.Cleanup(func() { setDialSSHConnection(origDial) })

	if err := processDueUpdatePolicies(now); err != nil {
		t.Fatalf("processDueUpdatePolicies() unexpected error: %v", err)
	}
	waitForCondition(t, 10*time.Second, func() bool {
		runs, err := listUpdatePolicyRuns(20)
		if err != nil {
			return false
		}
		for _, run := range runs {
			if run.PolicyID == autoApplyPolicy.ID && run.ServerName == alpha.Name && run.Status == updatePolicyRunSucceeded {
				return true
			}
		}
		return false
	}, "scheduled auto-apply run to succeed")

	if err := processDueUpdatePolicies(now); err != nil {
		t.Fatalf("second processDueUpdatePolicies() unexpected error: %v", err)
	}

	runs, err := listUpdatePolicyRuns(20)
	if err != nil {
		t.Fatalf("listUpdatePolicyRuns() unexpected error: %v", err)
	}
	if len(runs) != 5 {
		t.Fatalf("run count = %d, want 5", len(runs))
	}
	var foundSuperseded, foundBusy, foundBlackout, foundWinner bool
	for _, run := range runs {
		switch {
		case run.ServerName == alpha.Name && run.Status == updatePolicyRunSkipped && run.Reason == updatePolicyRunReasonSuperseded:
			foundSuperseded = true
		case run.ServerName == beta.Name && run.Status == updatePolicyRunSkipped && run.Reason == updatePolicyRunReasonBusy:
			foundBusy = true
		case run.ServerName == gamma.Name && run.Status == updatePolicyRunSkipped && run.Reason == updatePolicyRunReasonBlackout:
			foundBlackout = true
		case run.ServerName == alpha.Name && run.Status == updatePolicyRunSucceeded:
			foundWinner = true
		}
	}
	if !foundSuperseded || !foundBusy || !foundBlackout || !foundWinner {
		t.Fatalf("scheduler runs missing expected outcomes: superseded=%t busy=%t blackout=%t winner=%t runs=%+v", foundSuperseded, foundBusy, foundBlackout, foundWinner, runs)
	}
	if got := atomic.LoadInt32(&dialCalls); got != 1 {
		t.Fatalf("dial calls = %d, want 1", got)
	}
}

func TestMaintenancePageHTMLUsesAppTimezoneFormatting(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "maintenance-page-timezone.db")
	prepareUpdatePolicyTestState(t, dbFile)

	if _, err := saveAppTimezone("America/Toronto"); err != nil {
		t.Fatalf("saveAppTimezone() unexpected error: %v", err)
	}

	oldState := currentMaintenanceState()
	t.Cleanup(func() {
		setCurrentMaintenanceState(oldState)
	})
	setCurrentMaintenanceState(MaintenanceState{
		Active:    true,
		Kind:      jobKindBackupRestore,
		JobID:     "job-maint-timezone",
		StartedAt: "2026-01-15T12:34:56Z",
		Message:   "Timezone-aware maintenance page.",
	})

	html := maintenancePageHTML()
	if !strings.Contains(html, "America/Toronto") {
		t.Fatalf("maintenance HTML missing timezone label: %s", html)
	}
	if !strings.Contains(html, "2026-01-15 07:34:56 EST") {
		t.Fatalf("maintenance HTML missing localized timestamp: %s", html)
	}
}

func TestRunUpdateJobWithActorScheduledAutoApplyUsesJobMeta(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-auto-apply.db")
	prepareUpdatePolicyTestState(t, dbFile)

	t.Setenv(retryMaxAttemptsEnv, "1")
	t.Setenv(postchecksEnabledEnv, "false")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)

	server := Server{Name: "srv-auto-apply", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Tags: []string{"prod"}, Upgradable: []string{}},
	}
	mu.Unlock()

	meta := buildScheduledJobMeta(UpdatePolicy{
		ID:                     7,
		Name:                   "Auto apply full",
		ExecutionMode:          updatePolicyExecutionAutoApply,
		PackageScope:           updatePolicyPackageScopeFull,
		ApprovalTimeoutMinutes: defaultScheduledApprovalTimeoutMinutes,
	}, time.Now().UTC().Format(jobTimestampLayout))
	job, err := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: server.Name,
		Actor:      "system",
		Status:     jobStatusQueued,
		MetaJSON:   marshalJobJSON(meta),
	})
	if err != nil {
		t.Fatalf("CreateJob(update) unexpected error: %v", err)
	}

	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "2048000\n2097152\n"},
			precheckLocksCmd:     {err: fakeExitStatusError{code: 1, msg: "no process found"}},
			precheckDpkgAuditCmd: {},
			precheckAptCheckCmd:  {},
			aptUpdateCmd:         {},
			aptListUpgradableCmd: {stdout: "Inst openssl [3.0.0-1] (3.0.1-1 Debian-Security:12/stable-security [amd64])\nInst bash [5.2-1] (5.2-2 Debian:12 [amd64])\n"},
			aptUpgradeCmd:        {},
		},
	}
	origDial := getDialSSHConnection()
	var dialCalls int32
	setDialSSHConnection(func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		atomic.AddInt32(&dialCalls, 1)
		return conn, nil
	})
	t.Cleanup(func() { setDialSSHConnection(origDial) })

	done := make(chan struct{})
	go func() {
		runUpdateJobWithActor(server, "system", "", loadRetryPolicyFromEnv(), job.ID)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for scheduled auto-apply update to finish")
	}

	if got := atomic.LoadInt32(&dialCalls); got != 1 {
		t.Fatalf("dial calls = %d, want 1 for auto-apply path", got)
	}
	finalStatus := currentStatusSnapshot(server.Name)
	if finalStatus == nil || finalStatus.Status != "done" {
		t.Fatalf("final status = %+v, want done", finalStatus)
	}
	persistedJob, err := currentJobManager().GetJob(job.ID)
	if err != nil {
		t.Fatalf("GetJob(auto-apply) unexpected error: %v", err)
	}
	var persistedMeta scheduledJobMeta
	if err := json.Unmarshal([]byte(persistedJob.MetaJSON), &persistedMeta); err != nil {
		t.Fatalf("unmarshal job meta: %v", err)
	}
	if persistedMeta.Discovery == nil || persistedMeta.Discovery.PendingPackageCount != 2 {
		t.Fatalf("persisted discovery = %+v, want two pending packages", persistedMeta.Discovery)
	}
}

func TestRunUpdateJobWithActorScheduledApprovalRequiredCancelledKeepsMeta(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-approval-required.db")
	prepareUpdatePolicyTestState(t, dbFile)

	t.Setenv(retryMaxAttemptsEnv, "1")
	t.Setenv(postchecksEnabledEnv, "false")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)

	handler, sessionCookie := setupAuthenticatedHandler(t, dbFile)
	server := Server{Name: "srv-approval-required", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Tags: []string{"prod"}, Upgradable: []string{}},
	}
	mu.Unlock()

	scheduledFor := time.Now().UTC().Format(jobTimestampLayout)
	meta := buildScheduledJobMeta(UpdatePolicy{
		ID:                     9,
		Name:                   "Approval required security",
		ExecutionMode:          updatePolicyExecutionApprovalRequired,
		PackageScope:           updatePolicyPackageScopeSecurity,
		ApprovalTimeoutMinutes: defaultScheduledApprovalTimeoutMinutes,
	}, scheduledFor)
	job, err := currentJobManager().CreateJob(JobCreateParams{
		Kind:       jobKindUpdate,
		ServerName: server.Name,
		Actor:      "system",
		Status:     jobStatusQueued,
		MetaJSON:   marshalJobJSON(meta),
	})
	if err != nil {
		t.Fatalf("CreateJob(update) unexpected error: %v", err)
	}

	updateConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd: {stdout: "2048000\n2097152\n"},
			precheckLocksCmd:     {err: fakeExitStatusError{code: 1, msg: "no process found"}},
			precheckDpkgAuditCmd: {},
			precheckAptCheckCmd:  {},
			aptUpdateCmd:         {},
			aptListUpgradableCmd: {stdout: "Inst openssl [3.0.0-1] (3.0.1-1 Debian-Security:12/stable-security [amd64])\n"},
		},
	}
	cveConn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			buildPackageCVEQueryCmd("openssl"): {stdout: "CVE-2026-1003\n"},
		},
	}
	origDial := getDialSSHConnection()
	var dialCalls int32
	setDialSSHConnection(makeDialSSHValidator(server, &dialCalls, updateConn, cveConn))
	t.Cleanup(func() { setDialSSHConnection(origDial) })

	done := make(chan struct{})
	go func() {
		runUpdateJobWithActor(server, "system", "", loadRetryPolicyFromEnv(), job.ID)
		close(done)
	}()

	deadline := time.Now().Add(6 * time.Second)
	for {
		snapshot := currentStatusSnapshot(server.Name)
		if snapshot != nil && snapshot.Status == "pending_approval" {
			break
		}
		if time.Now().After(deadline) {
			persistedJob, jobErr := currentJobManager().GetJob(job.ID)
			t.Fatalf(
				"timed out waiting for pending approval; runtime_status=%+v job_err=%v job_status=%q job_phase=%q job_summary=%q",
				snapshot,
				jobErr,
				persistedJob.Status,
				persistedJob.Phase,
				persistedJob.Summary,
			)
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitForCondition(t, 3*time.Second, func() bool {
		persistedJob, err := currentJobManager().GetJob(job.ID)
		return err == nil && persistedJob.Status == jobStatusWaitingApproval
	}, "scheduled approval-required job status to become waiting_approval")

	cancelRec := httptest.NewRecorder()
	cancelReq := httptest.NewRequest(http.MethodPost, "/api/cancel/"+server.Name, nil)
	cancelReq.AddCookie(sessionCookie)
	markSameOriginAuthRequest(cancelReq)
	handler.ServeHTTP(cancelRec, cancelReq)
	if cancelRec.Code != http.StatusOK {
		t.Fatalf("cancel status = %d, want %d (body=%s)", cancelRec.Code, http.StatusOK, cancelRec.Body.String())
	}

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for approval-required flow to exit after cancel")
	}

	persistedJob, err := currentJobManager().GetJob(job.ID)
	if err != nil {
		t.Fatalf("GetJob(approval-required) unexpected error: %v", err)
	}
	if persistedJob.Status != jobStatusCancelled {
		t.Fatalf("approval-required final job status = %q, want %q", persistedJob.Status, jobStatusCancelled)
	}
	var persistedMeta scheduledJobMeta
	if err := json.Unmarshal([]byte(persistedJob.MetaJSON), &persistedMeta); err != nil {
		t.Fatalf("unmarshal approval-required job meta: %v", err)
	}
	if persistedMeta.Trigger != "scheduled" {
		t.Fatalf("approval-required meta trigger = %q, want %q", persistedMeta.Trigger, "scheduled")
	}
	if persistedMeta.ExecutionMode != updatePolicyExecutionApprovalRequired {
		t.Fatalf("approval-required meta execution_mode = %q, want %q", persistedMeta.ExecutionMode, updatePolicyExecutionApprovalRequired)
	}
	if persistedMeta.ScheduledFor != scheduledFor {
		t.Fatalf("approval-required meta scheduled_for = %q, want %q", persistedMeta.ScheduledFor, scheduledFor)
	}
	if persistedMeta.ApprovalTimeoutMinutes != defaultScheduledApprovalTimeoutMinutes {
		t.Fatalf("approval-required meta timeout = %d, want %d", persistedMeta.ApprovalTimeoutMinutes, defaultScheduledApprovalTimeoutMinutes)
	}

	var auditStatus, auditMetaJSON string
	if err := getDB().QueryRow(`
		SELECT status, meta_json
		  FROM audit_events
		 WHERE action = 'update.cancel' AND target_name = ?
		 ORDER BY id DESC
		 LIMIT 1
	`, server.Name).Scan(&auditStatus, &auditMetaJSON); err != nil {
		t.Fatalf("query update.cancel audit: %v", err)
	}
	if auditStatus != "success" {
		t.Fatalf("update.cancel audit status = %q, want %q", auditStatus, "success")
	}
	var auditMeta map[string]any
	if err := json.Unmarshal([]byte(auditMetaJSON), &auditMeta); err != nil {
		t.Fatalf("unmarshal update.cancel audit meta: %v", err)
	}
	if auditMeta == nil {
		t.Fatalf("update.cancel audit meta is nil")
	}
}

func TestScheduledScanPolicyStoresDiscoveryWithoutRuntimeMutation(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-scan.db")
	prepareUpdatePolicyTestState(t, dbFile)

	t.Setenv(retryMaxAttemptsEnv, "1")
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	t.Setenv("DEBIAN_UPDATER_KNOWN_HOSTS", knownHostsPath)

	server := Server{Name: "srv-scan-only", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"scan"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Tags: []string{"scan"}, Upgradable: []string{}},
	}
	mu.Unlock()

	policy, err := createUpdatePolicy(UpdatePolicy{
		Name:          "Scan only",
		Enabled:       true,
		TargetTag:     "scan",
		PackageScope:  updatePolicyPackageScopeSecurity,
		ExecutionMode: updatePolicyExecutionScanOnly,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     time.Now().In(time.Local).Format("15:04"),
	})
	if err != nil {
		t.Fatalf("create scan-only policy: %v", err)
	}
	run, inserted, err := createUpdatePolicyRun(UpdatePolicyRun{
		PolicyID:        policy.ID,
		PolicyName:      policy.Name,
		ServerName:      server.Name,
		ScheduledForUTC: time.Now().UTC().Format(jobTimestampLayout),
		ExecutionMode:   policy.ExecutionMode,
		PackageScope:    policy.PackageScope,
		Status:          updatePolicyRunQueued,
		Summary:         "Queued",
		ResultJSON:      "{}",
	})
	if err != nil || !inserted {
		t.Fatalf("createUpdatePolicyRun(scan-only) = (%+v, %t, %v), want inserted", run, inserted, err)
	}

	conn := &scriptedSSHConnection{
		responses: map[string]scriptedResponse{
			precheckDiskSpaceCmd:               {stdout: "2048000\n2097152\n"},
			precheckLocksCmd:                   {err: fakeExitStatusError{code: 1, msg: "no process found"}},
			precheckDpkgAuditCmd:               {},
			precheckAptCheckCmd:                {},
			aptUpdateCmd:                       {},
			aptListUpgradableCmd:               {stdout: "Inst openssl [3.0.0-1] (3.0.1-1 Debian-Security:12/stable-security [amd64])\n"},
			buildPackageCVEQueryCmd("openssl"): {stdout: "CVE-2026-1001\n"},
		},
	}
	origDial := getDialSSHConnection()
	setDialSSHConnection(func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		return conn, nil
	})
	t.Cleanup(func() { setDialSSHConnection(origDial) })

	runScheduledScanPolicy(run, policy, server)
	waitForCondition(t, 10*time.Second, func() bool {
		current, err := getUpdatePolicyRun(run.ID)
		return err == nil && current.Status == updatePolicyRunSucceeded
	}, "scan-only policy run to complete")

	currentRun, err := getUpdatePolicyRun(run.ID)
	if err != nil {
		t.Fatalf("getUpdatePolicyRun(scan-only) unexpected error: %v", err)
	}
	if !strings.Contains(currentRun.ResultJSON, "openssl") {
		t.Fatalf("scan-only result_json = %s, want openssl discovery", currentRun.ResultJSON)
	}
	if strings.TrimSpace(currentRun.JobID) == "" {
		t.Fatalf("scan-only run job_id is empty")
	}
	scanJob, err := currentJobManager().GetJob(currentRun.JobID)
	if err != nil {
		t.Fatalf("GetJob(scan-only) unexpected error: %v", err)
	}
	var scanMeta scheduledJobMeta
	if err := json.Unmarshal([]byte(scanJob.MetaJSON), &scanMeta); err != nil {
		t.Fatalf("unmarshal scan job meta: %v", err)
	}
	if scanMeta.ScheduledFor != run.ScheduledForUTC {
		t.Fatalf("scan scheduled_for = %q, want %q", scanMeta.ScheduledFor, run.ScheduledForUTC)
	}
	runtimeStatus := currentStatusSnapshot(server.Name)
	if runtimeStatus == nil || runtimeStatus.Status != "idle" {
		t.Fatalf("runtime status after scan-only = %+v, want idle", runtimeStatus)
	}
}

func TestRunScheduledUpdatePolicyMaintenanceModeSkipsRun(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-maintenance-update.db")
	prepareUpdatePolicyTestState(t, dbFile)

	server := Server{Name: "srv-maint-update", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"prod"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Tags: []string{"prod"}, Upgradable: []string{}},
	}
	mu.Unlock()

	policy, err := createUpdatePolicy(UpdatePolicy{
		Name:          "Maintenance update skip",
		Enabled:       true,
		TargetTag:     "prod",
		PackageScope:  updatePolicyPackageScopeSecurity,
		ExecutionMode: updatePolicyExecutionApprovalRequired,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     time.Now().In(time.Local).Format("15:04"),
	})
	if err != nil {
		t.Fatalf("create maintenance update policy: %v", err)
	}
	run, inserted, err := createUpdatePolicyRun(UpdatePolicyRun{
		PolicyID:        policy.ID,
		PolicyName:      policy.Name,
		ServerName:      server.Name,
		ScheduledForUTC: time.Now().UTC().Format(jobTimestampLayout),
		ExecutionMode:   policy.ExecutionMode,
		PackageScope:    policy.PackageScope,
		Status:          updatePolicyRunQueued,
		Summary:         "Queued",
		ResultJSON:      "{}",
	})
	if err != nil || !inserted {
		t.Fatalf("createUpdatePolicyRun(maintenance update) = (%+v, %t, %v), want inserted", run, inserted, err)
	}

	setCurrentMaintenanceState(MaintenanceState{
		Active:    true,
		Kind:      "backup_restore",
		JobID:     "job-maint-update",
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Actor:     "test",
	})
	t.Cleanup(func() {
		setCurrentMaintenanceState(MaintenanceState{})
	})

	runScheduledUpdatePolicy(run, policy, server)

	currentRun, err := getUpdatePolicyRun(run.ID)
	if err != nil {
		t.Fatalf("getUpdatePolicyRun(maintenance update) unexpected error: %v", err)
	}
	if currentRun.Status != updatePolicyRunSkipped {
		t.Fatalf("maintenance update status = %q, want %q", currentRun.Status, updatePolicyRunSkipped)
	}
	if currentRun.Reason != updatePolicyRunReasonMaintenance {
		t.Fatalf("maintenance update reason = %q, want %q", currentRun.Reason, updatePolicyRunReasonMaintenance)
	}
	if strings.TrimSpace(currentRun.JobID) != "" {
		t.Fatalf("maintenance update job_id = %q, want empty", currentRun.JobID)
	}
	runtimeStatus := currentStatusSnapshot(server.Name)
	if runtimeStatus == nil || runtimeStatus.Status != "idle" {
		t.Fatalf("runtime status after maintenance update skip = %+v, want idle", runtimeStatus)
	}
}

func TestRunScheduledScanPolicyMaintenanceModeSkipsRun(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "update-policy-maintenance-scan.db")
	prepareUpdatePolicyTestState(t, dbFile)

	server := Server{Name: "srv-maint-scan", Host: "example.org", Port: 22, User: "root", Pass: "pw", Tags: []string{"scan"}}
	mu.Lock()
	servers = []Server{server}
	statusMap = map[string]*ServerStatus{
		server.Name: {Name: server.Name, Status: "idle", Tags: []string{"scan"}, Upgradable: []string{}},
	}
	mu.Unlock()

	policy, err := createUpdatePolicy(UpdatePolicy{
		Name:          "Maintenance scan skip",
		Enabled:       true,
		TargetTag:     "scan",
		PackageScope:  updatePolicyPackageScopeSecurity,
		ExecutionMode: updatePolicyExecutionScanOnly,
		CadenceKind:   updatePolicyCadenceDaily,
		TimeLocal:     time.Now().In(time.Local).Format("15:04"),
	})
	if err != nil {
		t.Fatalf("create maintenance scan policy: %v", err)
	}
	run, inserted, err := createUpdatePolicyRun(UpdatePolicyRun{
		PolicyID:        policy.ID,
		PolicyName:      policy.Name,
		ServerName:      server.Name,
		ScheduledForUTC: time.Now().UTC().Format(jobTimestampLayout),
		ExecutionMode:   policy.ExecutionMode,
		PackageScope:    policy.PackageScope,
		Status:          updatePolicyRunQueued,
		Summary:         "Queued",
		ResultJSON:      "{}",
	})
	if err != nil || !inserted {
		t.Fatalf("createUpdatePolicyRun(maintenance scan) = (%+v, %t, %v), want inserted", run, inserted, err)
	}

	setCurrentMaintenanceState(MaintenanceState{
		Active:    true,
		Kind:      "backup_restore",
		JobID:     "job-maint-scan",
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Actor:     "test",
	})
	t.Cleanup(func() {
		setCurrentMaintenanceState(MaintenanceState{})
	})

	runScheduledScanPolicy(run, policy, server)

	currentRun, err := getUpdatePolicyRun(run.ID)
	if err != nil {
		t.Fatalf("getUpdatePolicyRun(maintenance scan) unexpected error: %v", err)
	}
	if currentRun.Status != updatePolicyRunSkipped {
		t.Fatalf("maintenance scan status = %q, want %q", currentRun.Status, updatePolicyRunSkipped)
	}
	if currentRun.Reason != updatePolicyRunReasonMaintenance {
		t.Fatalf("maintenance scan reason = %q, want %q", currentRun.Reason, updatePolicyRunReasonMaintenance)
	}
	if strings.TrimSpace(currentRun.JobID) != "" {
		t.Fatalf("maintenance scan job_id = %q, want empty", currentRun.JobID)
	}
	runtimeStatus := currentStatusSnapshot(server.Name)
	if runtimeStatus == nil || runtimeStatus.Status != "idle" {
		t.Fatalf("runtime status after maintenance scan skip = %+v, want idle", runtimeStatus)
	}
}

func strconvFormatInt(v int64) string {
	return strconv.FormatInt(v, 10)
}
