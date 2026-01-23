package main

import "testing"

func TestNormalizePort(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{"zero defaults to 22", 0, 22},
		{"negative defaults to 22", -5, 22},
		{"too high defaults to 22", 70000, 22},
		{"valid port preserved", 2222, 2222},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizePort(tt.in); got != tt.want {
				t.Fatalf("normalizePort(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseTagsAndJoinTags(t *testing.T) {
	parsed := parseTags(" web, db , , api,web ")
	joined := joinTags(parsed)
	if joined != "web, db, api" {
		t.Fatalf("joinTags(parseTags()) = %q, want %q", joined, "web, db, api")
	}
}
