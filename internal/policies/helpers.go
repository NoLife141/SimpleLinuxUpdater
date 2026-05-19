package policies

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"debian-updater/internal/servers"
)

func ParseBlackouts(raw string) ([]BlackoutWindow, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []BlackoutWindow{}, nil
	}
	var windows []BlackoutWindow
	if err := json.Unmarshal([]byte(raw), &windows); err != nil {
		return nil, err
	}
	return NormalizeBlackouts(windows)
}

func ParseWeekdaysJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	var weekdays []string
	if err := json.Unmarshal([]byte(raw), &weekdays); err != nil {
		return []string{}
	}
	normalized, err := NormalizeWeekdays(weekdays)
	if err != nil {
		return []string{}
	}
	return normalized
}

func ParseStringListJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return []string{}
	}
	return NormalizeStringList(values)
}

func NormalizeStringList(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		clean := strings.TrimSpace(value)
		if clean == "" {
			continue
		}
		key := strings.ToLower(clean)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, clean)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

func NormalizeWeekdayToken(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "mon", "monday":
		return "mon", nil
	case "tue", "tues", "tuesday":
		return "tue", nil
	case "wed", "wednesday":
		return "wed", nil
	case "thu", "thur", "thurs", "thursday":
		return "thu", nil
	case "fri", "friday":
		return "fri", nil
	case "sat", "saturday":
		return "sat", nil
	case "sun", "sunday":
		return "sun", nil
	default:
		return "", fmt.Errorf("invalid weekday %q", raw)
	}
}

func NormalizeWeekdays(weekdays []string) ([]string, error) {
	if len(weekdays) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(weekdays))
	out := make([]string, 0, len(weekdays))
	for _, weekday := range weekdays {
		normalized, err := NormalizeWeekdayToken(weekday)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		return WeekdayOrder(out[i]) < WeekdayOrder(out[j])
	})
	return out, nil
}

func WeekdayOrder(day string) int {
	switch day {
	case "mon":
		return 1
	case "tue":
		return 2
	case "wed":
		return 3
	case "thu":
		return 4
	case "fri":
		return 5
	case "sat":
		return 6
	case "sun":
		return 7
	default:
		return 99
	}
}

func NormalizeTimeLocal(raw string) (string, error) {
	parsed, err := time.Parse("15:04", strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("time_local must be HH:MM")
	}
	return parsed.Format("15:04"), nil
}

func ParseTimeLocalMinutes(raw string) (int, error) {
	normalized, err := NormalizeTimeLocal(raw)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(normalized, ":")
	hour, _ := strconv.Atoi(parts[0])
	minute, _ := strconv.Atoi(parts[1])
	return hour*60 + minute, nil
}

func NormalizeBlackouts(windows []BlackoutWindow) ([]BlackoutWindow, error) {
	if len(windows) == 0 {
		return []BlackoutWindow{}, nil
	}
	normalized := make([]BlackoutWindow, 0, len(windows))
	for _, window := range windows {
		weekdays, err := NormalizeWeekdays(window.Weekdays)
		if err != nil {
			return nil, err
		}
		if len(weekdays) == 0 {
			return nil, errors.New("blackout weekdays are required")
		}
		startTime, err := NormalizeTimeLocal(window.StartTime)
		if err != nil {
			return nil, fmt.Errorf("invalid blackout start_time: %w", err)
		}
		endTime, err := NormalizeTimeLocal(window.EndTime)
		if err != nil {
			return nil, fmt.Errorf("invalid blackout end_time: %w", err)
		}
		startMinutes, _ := ParseTimeLocalMinutes(startTime)
		endMinutes, _ := ParseTimeLocalMinutes(endTime)
		if startMinutes == endMinutes {
			return nil, errors.New("blackout start_time and end_time cannot be identical")
		}
		normalized = append(normalized, BlackoutWindow{
			Weekdays:  weekdays,
			StartTime: startTime,
			EndTime:   endTime,
		})
	}
	return normalized, nil
}

func ServerHasTag(server servers.Server, tag string) bool {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return false
	}
	for _, candidate := range server.Tags {
		if strings.EqualFold(strings.TrimSpace(candidate), tag) {
			return true
		}
	}
	return false
}

func ServerHasAnyTag(server servers.Server, tags []string) bool {
	for _, tag := range tags {
		if ServerHasTag(server, tag) {
			return true
		}
	}
	return false
}

func StringListContainsFold(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), needle) {
			return true
		}
	}
	return false
}

func BoolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func marshalJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func sortStrings(values []string) {
	sort.Strings(values)
}

func NextWeekdayToken(token string) string {
	switch token {
	case "mon":
		return "tue"
	case "tue":
		return "wed"
	case "wed":
		return "thu"
	case "thu":
		return "fri"
	case "fri":
		return "sat"
	case "sat":
		return "sun"
	default:
		return "mon"
	}
}

func CanonicalScheduledForUTC(slotLocal time.Time, layout string, fallbackLocation func() *time.Location) string {
	loc := slotLocal.Location()
	if loc == nil && fallbackLocation != nil {
		loc = fallbackLocation()
	}
	if loc == nil {
		loc = time.UTC
	}
	if strings.TrimSpace(layout) == "" {
		layout = DefaultTimestampLayout
	}
	canonicalLocal := time.Date(
		slotLocal.Year(),
		slotLocal.Month(),
		slotLocal.Day(),
		slotLocal.Hour(),
		slotLocal.Minute(),
		0,
		0,
		loc,
	)
	return canonicalLocal.UTC().Format(layout)
}
