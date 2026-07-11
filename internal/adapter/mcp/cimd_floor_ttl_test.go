package mcp

import (
	"testing"
	"time"
)

func TestCacheTTLFromCacheControl_AppliesFloor(t *testing.T) {
	fallback := 5 * time.Minute
	cases := []struct {
		name string
		hdr  string
		want time.Duration
	}{
		{"no header falls back to fallback", "", fallback},
		{"no-store is raised to floor", "no-store", cimdFloorTTL},
		{"no-cache is raised to floor", "no-cache", cimdFloorTTL},
		{"max-age=0 is raised to floor", "max-age=0", cimdFloorTTL},
		{"max-age below floor is raised", "max-age=1", cimdFloorTTL},
		{"max-age equal to floor is kept", "max-age=5", cimdFloorTTL},
		{"max-age above floor is kept verbatim", "max-age=600", 600 * time.Second},
		{"unparseable max-age is raised to floor", "max-age=abc", cimdFloorTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cacheTTLFromCacheControl(tc.hdr, fallback); got != tc.want {
				t.Errorf("cacheTTLFromCacheControl(%q) = %v, want %v", tc.hdr, got, tc.want)
			}
		})
	}
}

func TestCacheTTLFromCacheControl_AppliesCeiling(t *testing.T) {
	fallback := 5 * time.Minute
	cases := []struct {
		name string
		hdr  string
		want time.Duration
	}{
		{"max-age below ceiling is kept verbatim", "max-age=86399", 86399 * time.Second},
		{"max-age equal to ceiling is kept", "max-age=86400", cimdCeilTTL},
		{"max-age above ceiling is clamped", "max-age=99999999", cimdCeilTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cacheTTLFromCacheControl(tc.hdr, fallback); got != tc.want {
				t.Errorf("cacheTTLFromCacheControl(%q) = %v, want %v", tc.hdr, got, tc.want)
			}
		})
	}
}
