package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const maintenanceStateSetting = "maintenance_state"

var (
	errMaintenanceModeActive = errors.New("maintenance mode active")

	maintenanceStateMu sync.RWMutex
	maintenanceState   MaintenanceState
)

type MaintenanceState struct {
	Active    bool   `json:"active"`
	Kind      string `json:"kind"`
	JobID     string `json:"job_id"`
	StartedAt string `json:"started_at"`
	Actor     string `json:"actor"`
	Message   string `json:"message"`
}

func currentMaintenanceState() MaintenanceState {
	maintenanceStateMu.RLock()
	defer maintenanceStateMu.RUnlock()
	return maintenanceState
}

func setCurrentMaintenanceState(state MaintenanceState) {
	maintenanceStateMu.Lock()
	defer maintenanceStateMu.Unlock()
	maintenanceState = state
}

func initializeMaintenanceState() error {
	state, err := loadPersistedMaintenanceState()
	if err != nil {
		return err
	}
	if state.Active {
		state = MaintenanceState{}
		if err := persistMaintenanceState(state); err != nil {
			return err
		}
	}
	setCurrentMaintenanceState(state)
	return nil
}

func loadPersistedMaintenanceState() (MaintenanceState, error) {
	var raw string
	err := getDB().QueryRow("SELECT value FROM settings WHERE key = ?", maintenanceStateSetting).Scan(&raw)
	if err == sql.ErrNoRows {
		return MaintenanceState{}, nil
	}
	if err != nil {
		return MaintenanceState{}, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return MaintenanceState{}, nil
	}
	var state MaintenanceState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return MaintenanceState{}, err
	}
	return state, nil
}

func persistMaintenanceState(state MaintenanceState) error {
	blob, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if _, err := getDB().Exec(
		"INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		maintenanceStateSetting,
		string(blob),
	); err != nil {
		return err
	}
	return nil
}

func activateMaintenance(kind, jobID, actor, message string) error {
	state := MaintenanceState{
		Active:    true,
		Kind:      strings.TrimSpace(kind),
		JobID:     strings.TrimSpace(jobID),
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Actor:     strings.TrimSpace(actor),
		Message:   strings.TrimSpace(message),
	}
	if err := persistMaintenanceState(state); err != nil {
		return err
	}
	setCurrentMaintenanceState(state)
	return nil
}

func deactivateMaintenance() error {
	state := MaintenanceState{}
	if err := persistMaintenanceState(state); err != nil {
		return err
	}
	setCurrentMaintenanceState(state)
	return nil
}

func publicMaintenanceStatePayload() gin.H {
	state := currentMaintenanceState()
	return gin.H{
		"active":     state.Active,
		"kind":       state.Kind,
		"started_at": state.StartedAt,
		"message":    state.Message,
	}
}

func maintenanceResponsePayload() gin.H {
	payload := publicMaintenanceStatePayload()
	payload["error"] = "maintenance mode active"
	payload["maintenance"] = true
	return payload
}

func maintenancePageHTML() string {
	state := currentMaintenanceState()
	message := "Maintenance is in progress. Please wait while the updater finishes a backup operation."
	if strings.TrimSpace(state.Message) != "" {
		message = state.Message
	}
	kind := strings.ReplaceAll(strings.TrimSpace(state.Kind), "_", " ")
	if kind == "" {
		kind = "maintenance"
	}
	startedAtDisplay, timezoneLabel := formatTimestampForAppDisplay(state.StartedAt)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Maintenance Mode</title>
  <link rel="stylesheet" href="/static/css/maintenance.css">
</head>
<body>
  <main>
    <div class="pulse" aria-hidden="true"></div>
    <h1>Maintenance Mode</h1>
    <p>%s</p>
    <div class="meta">
      <div class="label">Current Operation</div>
      <div class="value">%s</div>
    </div>
    <div class="meta">
      <div class="label">Started</div>
      <div class="value">%s</div>
    </div>
    <div class="meta">
      <div class="label">Timezone</div>
      <div class="value">%s</div>
    </div>
  </main>
  <script src="/static/js/maintenance.js"></script>
</body>
</html>`,
		html.EscapeString(message),
		html.EscapeString(kind),
		html.EscapeString(startedAtDisplay),
		html.EscapeString(timezoneLabel),
	)
}

func writeMaintenanceBlockedResponse(c *gin.Context) {
	if c == nil {
		return
	}
	payload := maintenanceResponsePayload()
	if c.Request != nil {
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/") || path == "/metrics" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, payload)
			return
		}
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusServiceUnavailable)
	_, _ = c.Writer.WriteString(maintenancePageHTML())
	c.Abort()
}

func maintenanceBypassPath(path string) bool {
	switch {
	case path == "/api/maintenance":
		return true
	case strings.HasPrefix(path, "/static/"):
		return true
	default:
		return false
	}
}

func maintenanceExclusivePath(path string) bool {
	switch path {
	case "/api/backup/export", "/api/backup/restore":
		return true
	default:
		return false
	}
}

func handleMaintenanceStatus(c *gin.Context) {
	c.JSON(http.StatusOK, publicMaintenanceStatePayload())
}
