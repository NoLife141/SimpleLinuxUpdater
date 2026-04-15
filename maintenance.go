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

func maintenanceResponsePayload() gin.H {
	state := currentMaintenanceState()
	return gin.H{
		"error":       "maintenance mode active",
		"maintenance": true,
		"kind":        state.Kind,
		"started_at":  state.StartedAt,
		"job_id":      state.JobID,
	}
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
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Maintenance Mode</title>
  <style>
    :root {
      --bg: #0b1220;
      --card: #131c31;
      --card-alt: #1a2540;
      --text: #eef3ff;
      --subtle: #a7b4d0;
      --accent: #5ec2a8;
      --border: rgba(167, 180, 208, 0.22);
      --shadow: 0 24px 60px rgba(3, 8, 20, 0.45);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", Helvetica, Arial, sans-serif;
      background:
        radial-gradient(circle at top, rgba(94, 194, 168, 0.18), transparent 42%%),
        linear-gradient(180deg, #0b1220 0%%, #10182b 100%%);
      color: var(--text);
      display: grid;
      place-items: center;
      padding: 24px;
    }
    main {
      width: min(560px, 100%%);
      background: linear-gradient(180deg, var(--card), var(--card-alt));
      border: 1px solid var(--border);
      border-radius: 24px;
      box-shadow: var(--shadow);
      padding: 32px;
    }
    h1 {
      margin: 0 0 12px;
      font-size: clamp(2rem, 3vw, 2.6rem);
    }
    p {
      margin: 0 0 16px;
      color: var(--subtle);
      line-height: 1.6;
    }
    .meta {
      margin-top: 24px;
      padding: 16px;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.06);
    }
    .label {
      color: var(--subtle);
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.08em;
    }
    .value {
      margin-top: 6px;
      font-size: 1rem;
    }
    .pulse {
      width: 12px;
      height: 12px;
      border-radius: 999px;
      background: var(--accent);
      box-shadow: 0 0 0 rgba(94, 194, 168, 0.5);
      animation: pulse 1.8s infinite;
      margin-bottom: 18px;
    }
    @keyframes pulse {
      0%% { box-shadow: 0 0 0 0 rgba(94, 194, 168, 0.45); }
      70%% { box-shadow: 0 0 0 18px rgba(94, 194, 168, 0); }
      100%% { box-shadow: 0 0 0 0 rgba(94, 194, 168, 0); }
    }
  </style>
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
  </main>
  <script>
    (function poll() {
      fetch('/api/maintenance', { credentials: 'same-origin', cache: 'no-store' })
        .then(function (response) { return response.json(); })
        .then(function (data) {
          if (!data || !data.active) {
            window.location.reload();
            return;
          }
          window.setTimeout(poll, 1500);
        })
        .catch(function () {
          window.setTimeout(poll, 2000);
        });
    })();
  </script>
</body>
</html>`,
		html.EscapeString(message),
		html.EscapeString(kind),
		html.EscapeString(state.StartedAt),
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
	c.JSON(http.StatusOK, currentMaintenanceState())
}
