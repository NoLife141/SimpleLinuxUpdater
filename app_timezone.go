package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/gin-gonic/gin"
)

const appTimezoneSetting = "app_timezone"
const appDisplayTimestampLayout = "2006-01-02 15:04:05 MST"
const appTimezoneLocalDisplayLabel = "Server local time"

var errAppTimezoneValidation = errors.New("app timezone validation")
var detectSystemTimezoneNameFunc = detectSystemTimezoneName
var offsetTimezonePattern = regexp.MustCompile(`^([+-])(\d{2}):(\d{2})$`)
var appTimezoneMetadataPaths = []string{"/etc/timezone", "/etc/TZ"}
var appTimezoneLocaltimePath = "/etc/localtime"
var appTimezoneZoneinfoRoots = []string{
	"/usr/share/zoneinfo",
	"/usr/lib/zoneinfo",
	"/usr/share/lib/zoneinfo",
	"/etc/zoneinfo",
}

type AppTimezoneResponse struct {
	Timezone         string `json:"timezone"`
	ResolvedTimezone string `json:"resolved_timezone,omitempty"`
}

func wrapAppTimezoneValidationError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", errAppTimezoneValidation, err)
}

func isAppTimezoneValidationError(err error) bool {
	return errors.Is(err, errAppTimezoneValidation)
}

func defaultAppLocation() *time.Location {
	if time.Local != nil {
		return time.Local
	}
	return time.UTC
}

func offsetTimezoneLabel(offsetSeconds int) string {
	if offsetSeconds == 0 {
		return "UTC"
	}
	sign := "+"
	if offsetSeconds < 0 {
		sign = "-"
		offsetSeconds = -offsetSeconds
	}
	hours := offsetSeconds / 3600
	minutes := (offsetSeconds % 3600) / 60
	return fmt.Sprintf("%s%02d:%02d", sign, hours, minutes)
}

func locationHasVariableOffset(loc *time.Location, at time.Time) bool {
	if loc == nil {
		return false
	}
	samples := []time.Time{
		at.UTC(),
		at.AddDate(0, -6, 0).UTC(),
		at.AddDate(0, 6, 0).UTC(),
		time.Date(at.Year(), time.January, 1, 12, 0, 0, 0, time.UTC),
		time.Date(at.Year(), time.July, 1, 12, 0, 0, 0, time.UTC),
		time.Date(at.Year()+1, time.January, 1, 12, 0, 0, 0, time.UTC),
	}
	offsets := make(map[int]struct{}, len(samples))
	for _, sample := range samples {
		_, offset := sample.In(loc).Zone()
		offsets[offset] = struct{}{}
		if len(offsets) > 1 {
			return true
		}
	}
	return false
}

func browserSafeTimezoneLabelForLocation(loc *time.Location, at time.Time) string {
	if loc == nil {
		return "UTC"
	}
	if name := validateTimezoneName(loc.String()); name != "" && !strings.EqualFold(name, "Local") {
		return name
	}
	if locationHasVariableOffset(loc, at) {
		return "Local"
	}
	_, offset := at.In(loc).Zone()
	return offsetTimezoneLabel(offset)
}

func isLocalTimezoneAlias(raw string) bool {
	value := strings.TrimSpace(raw)
	return strings.EqualFold(value, "Local") || strings.EqualFold(value, appTimezoneLocalDisplayLabel)
}

func appTimezoneDisplayAndResolved(loc *time.Location, name string, at time.Time) (string, string) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "UTC", "UTC"
	}
	if isLocalTimezoneAlias(trimmed) {
		return appTimezoneLocalDisplayLabel, ""
	}
	return trimmed, trimmed
}

func defaultAppTimezone() (*time.Location, string) {
	name, err := detectSystemTimezoneNameFunc()
	if err == nil && strings.TrimSpace(name) != "" && !strings.EqualFold(name, "Local") {
		if offsetName, offsetLoc, ok := parseOffsetTimezoneLabel(name); ok {
			return offsetLoc, offsetName
		}
		loc, loadErr := time.LoadLocation(name)
		if loadErr == nil {
			return loc, loc.String()
		}
		log.Printf("default app timezone fallback for %q: %v", name, loadErr)
	} else if err != nil {
		log.Printf("default app timezone fallback: %v", err)
	}
	loc := defaultAppLocation()
	if loc == nil {
		loc = time.UTC
	}
	return loc, browserSafeTimezoneLabelForLocation(loc, time.Now())
}

func defaultAppTimezoneName() string {
	_, name := defaultAppTimezone()
	return name
}

func browserSafeTimezoneName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || strings.EqualFold(name, "Local") {
		return false
	}
	switch {
	case strings.EqualFold(name, "UTC"):
		return true
	case strings.HasPrefix(name, "Etc/"):
		return true
	case strings.HasPrefix(name, "right/"),
		strings.HasPrefix(name, "posix/"),
		strings.HasPrefix(name, "SystemV/"):
		return false
	case strings.Contains(name, "/"):
		return true
	case strings.EqualFold(name, "Factory"),
		strings.EqualFold(name, "posixrules"):
		return false
	default:
		return true
	}
}

func normalizeTimezoneCandidate(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, ":")
	return value
}

func timezoneNameFromZoneinfoPath(path string) string {
	raw := strings.TrimSpace(path)
	if raw == "" {
		return ""
	}
	normalized := filepath.ToSlash(raw)
	for _, marker := range []string{"/zoneinfo/", "zoneinfo/"} {
		if idx := strings.Index(normalized, marker); idx >= 0 {
			name := strings.Trim(normalized[idx+len(marker):], "/")
			if name != "" {
				return name
			}
		}
	}
	return ""
}

func validateTimezoneName(raw string) string {
	name := normalizeTimezoneCandidate(raw)
	if name == "" {
		return ""
	}
	if _, _, ok := parseOffsetTimezoneLabel(name); ok {
		return name
	}
	if _, err := time.LoadLocation(name); err != nil {
		return ""
	}
	if !browserSafeTimezoneName(name) {
		return ""
	}
	return name
}

func parseOffsetTimezoneLabel(raw string) (string, *time.Location, bool) {
	name := normalizeTimezoneCandidate(raw)
	match := offsetTimezonePattern.FindStringSubmatch(name)
	if match == nil {
		return "", nil, false
	}
	hours, err := strconv.Atoi(match[2])
	if err != nil || hours > 23 {
		return "", nil, false
	}
	minutes, err := strconv.Atoi(match[3])
	if err != nil || minutes > 59 {
		return "", nil, false
	}
	offset := hours*3600 + minutes*60
	if match[1] == "-" {
		offset = -offset
	}
	return name, time.FixedZone(name, offset), true
}

func localtimeTimezoneCandidateAllowed(name string) bool {
	if name == "" || strings.EqualFold(name, "Local") {
		return false
	}
	switch {
	case strings.HasPrefix(name, "right/"),
		strings.HasPrefix(name, "posix/"),
		strings.HasPrefix(name, "SystemV/"):
		return false
	case strings.Contains(name, "/"):
		return true
	case name == "UTC":
		return true
	case strings.HasPrefix(name, "Etc/"):
		return true
	default:
		return false
	}
}

func localtimeTimezoneCandidateScore(name string) int {
	switch {
	case name == "UTC":
		return 0
	case strings.HasPrefix(name, "Etc/"):
		return 3
	case strings.HasPrefix(name, "US/"),
		strings.HasPrefix(name, "Canada/"),
		strings.HasPrefix(name, "Mexico/"),
		strings.HasPrefix(name, "Brazil/"),
		strings.HasPrefix(name, "Chile/"):
		return 2
	default:
		return 1
	}
}

func preferLocaltimeTimezoneCandidate(candidate, current string) bool {
	if current == "" {
		return true
	}
	candidateScore := localtimeTimezoneCandidateScore(candidate)
	currentScore := localtimeTimezoneCandidateScore(current)
	if candidateScore != currentScore {
		return candidateScore < currentScore
	}
	if len(candidate) != len(current) {
		return len(candidate) < len(current)
	}
	return candidate < current
}

func detectTimezoneNameFromLocaltimeFile(path string) (string, error) {
	localtimePath := strings.TrimSpace(path)
	if localtimePath == "" {
		return "", errors.New("localtime path is required")
	}
	localtimeBytes, err := os.ReadFile(localtimePath)
	if err != nil {
		return "", err
	}
	if len(localtimeBytes) == 0 {
		return "", errors.New("localtime file is empty")
	}
	bestMatch := ""
	for _, root := range appTimezoneZoneinfoRoots {
		zoneinfoRoot := strings.TrimSpace(root)
		if zoneinfoRoot == "" {
			continue
		}
		walkErr := filepath.WalkDir(zoneinfoRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path != zoneinfoRoot {
					switch d.Name() {
					case "right", "posix":
						return filepath.SkipDir
					}
				}
				return nil
			}
			rel, err := filepath.Rel(zoneinfoRoot, path)
			if err != nil {
				return nil
			}
			name := validateTimezoneName(filepath.ToSlash(rel))
			if !localtimeTimezoneCandidateAllowed(name) {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() != int64(len(localtimeBytes)) {
				return nil
			}
			candidateBytes, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(candidateBytes, localtimeBytes) {
				return nil
			}
			if preferLocaltimeTimezoneCandidate(name, bestMatch) {
				bestMatch = name
			}
			return nil
		})
		if walkErr == nil && bestMatch != "" {
			return bestMatch, nil
		}
	}
	return "", errors.New("could not match localtime contents to zoneinfo database")
}

func detectTimezoneNameFromLocaltime(path string) (string, error) {
	localtimePath := strings.TrimSpace(path)
	if localtimePath == "" {
		return "", errors.New("localtime path is required")
	}
	if resolved, err := filepath.EvalSymlinks(localtimePath); err == nil {
		if name := validateTimezoneName(timezoneNameFromZoneinfoPath(resolved)); name != "" {
			return name, nil
		}
	}
	if target, err := os.Readlink(localtimePath); err == nil {
		if name := validateTimezoneName(timezoneNameFromZoneinfoPath(target)); name != "" {
			return name, nil
		}
	}
	return detectTimezoneNameFromLocaltimeFile(localtimePath)
}

func detectSystemTimezoneName() (string, error) {
	if name := validateTimezoneName(os.Getenv("TZ")); name != "" {
		return name, nil
	}
	if name := validateTimezoneName(defaultAppLocation().String()); name != "" && !strings.EqualFold(name, "Local") {
		return name, nil
	}
	if name, err := detectTimezoneNameFromLocaltime(appTimezoneLocaltimePath); err == nil && name != "" {
		return name, nil
	}
	for _, path := range appTimezoneMetadataPaths {
		if data, err := os.ReadFile(path); err == nil {
			if name := validateTimezoneName(string(data)); name != "" {
				return name, nil
			}
		}
	}
	return "", errors.New("could not resolve system local timezone name")
}

func resolveAppTimezone(raw string) (string, *time.Location, error) {
	name := normalizeTimezoneCandidate(raw)
	if name == "" {
		return "", nil, errors.New("timezone is required")
	}
	if isLocalTimezoneAlias(name) {
		detected, err := detectSystemTimezoneNameFunc()
		if err != nil {
			loc := defaultAppLocation()
			if loc == nil {
				loc = time.UTC
			}
			if fallbackName := browserSafeTimezoneLabelForLocation(loc, time.Now()); fallbackName != "" && !strings.EqualFold(fallbackName, "Local") {
				if offsetName, offsetLoc, ok := parseOffsetTimezoneLabel(fallbackName); ok {
					return offsetName, offsetLoc, nil
				}
				if fallbackLoc, loadErr := time.LoadLocation(fallbackName); loadErr == nil {
					return fallbackLoc.String(), fallbackLoc, nil
				}
			}
			return "Local", loc, nil
		}
		name = detected
	}
	if !browserSafeTimezoneName(name) {
		return "", nil, fmt.Errorf("invalid timezone %q", name)
	}
	if offsetName, offsetLoc, ok := parseOffsetTimezoneLabel(name); ok {
		return offsetName, offsetLoc, nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return "", nil, fmt.Errorf("invalid timezone %q", name)
	}
	if strings.EqualFold(loc.String(), "Local") {
		detected, err := detectSystemTimezoneNameFunc()
		if err != nil {
			return "", nil, err
		}
		name = detected
		loc, err = time.LoadLocation(name)
		if err != nil {
			return "", nil, fmt.Errorf("invalid timezone %q", name)
		}
	}
	return loc.String(), loc, nil
}

func normalizeAppTimezoneName(raw string) (string, *time.Location, error) {
	name, loc, err := resolveAppTimezone(raw)
	if err != nil {
		return "", nil, wrapAppTimezoneValidationError(err)
	}
	return name, loc, nil
}

func loadCurrentAppTimezone() (*time.Location, string, error) {
	fallbackLoc, fallbackName := defaultAppTimezone()

	var err error
	raw, err := getSettingValue(appTimezoneSetting)
	if err != nil {
		return fallbackLoc, fallbackName, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallbackLoc, fallbackName, nil
	}
	name, loc, err := resolveAppTimezone(raw)
	if err != nil {
		return fallbackLoc, fallbackName, fmt.Errorf("load configured app timezone %q: %w", raw, err)
	}
	return loc, name, nil
}

func currentAppTimezone() (*time.Location, string) {
	loc, name, err := loadCurrentAppTimezone()
	if err != nil {
		log.Printf("app timezone fallback to %s: %v", name, err)
	}
	if loc == nil {
		loc = time.UTC
	}
	if strings.TrimSpace(name) == "" {
		name = "UTC"
	}
	return loc, name
}

func currentAppLocation() *time.Location {
	loc, _ := currentAppTimezone()
	return loc
}

func currentAppTimezoneName() string {
	_, name := currentAppTimezone()
	return name
}

func currentAppTimezoneDisplayName() string {
	loc, name := currentAppTimezone()
	display, _ := appTimezoneDisplayAndResolved(loc, name, time.Now())
	return display
}

func currentAppTimezoneResolvedName() string {
	loc, name := currentAppTimezone()
	_, resolved := appTimezoneDisplayAndResolved(loc, name, time.Now())
	return resolved
}

func currentAppTimezoneResponse() AppTimezoneResponse {
	return AppTimezoneResponse{
		Timezone:         currentAppTimezoneDisplayName(),
		ResolvedTimezone: currentAppTimezoneResolvedName(),
	}
}

func saveAppTimezone(raw string) (string, error) {
	name, _, err := normalizeAppTimezoneName(raw)
	if err != nil {
		return "", err
	}
	if err := upsertSettingValue(appTimezoneSetting, name); err != nil {
		return "", err
	}
	return name, nil
}

func parseAppTimestamp(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, errors.New("timestamp is required")
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		jobTimestampLayout,
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp format %q", value)
}

func formatTimestampForAppDisplayWithTimezone(raw string, loc *time.Location, timezoneName string) (string, string) {
	if loc == nil {
		loc = time.UTC
	}
	if strings.TrimSpace(timezoneName) == "" {
		timezoneName = "UTC"
	}
	parsed, err := parseAppTimestamp(raw)
	if err != nil {
		value := strings.TrimSpace(raw)
		display, _ := appTimezoneDisplayAndResolved(loc, timezoneName, time.Now())
		if value == "" {
			return "-", display
		}
		return value, display
	}
	display, _ := appTimezoneDisplayAndResolved(loc, timezoneName, parsed)
	return parsed.In(loc).Format(appDisplayTimestampLayout), display
}

func formatTimestampForAppDisplay(raw string) (string, string) {
	loc, timezoneName := currentAppTimezone()
	return formatTimestampForAppDisplayWithTimezone(raw, loc, timezoneName)
}

func handleAppTimezoneStatus(c *gin.Context) {
	c.JSON(http.StatusOK, currentAppTimezoneResponse())
}

func handleAppTimezoneUpdate(c *gin.Context) {
	var req AppTimezoneResponse
	if err := c.ShouldBindJSON(&req); err != nil {
		audit(c, "app_settings.timezone", "settings", "app_timezone", "failure", "Invalid app timezone payload", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	timezone, err := saveAppTimezone(req.Timezone)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if isAppTimezoneValidationError(err) {
			statusCode = http.StatusBadRequest
		}
		audit(c, "app_settings.timezone", "settings", "app_timezone", "failure", "Failed to save app timezone", map[string]any{"error": err.Error()})
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}
	audit(c, "app_settings.timezone", "settings", "app_timezone", "success", "App timezone saved", map[string]any{"timezone": timezone})
	c.JSON(http.StatusOK, currentAppTimezoneResponse())
}
