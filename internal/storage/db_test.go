package storage

import (
	"testing"
)

func TestUser_IsActive(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"active", true},
		{"disabled", false},
		{"pending_deletion", false},
		{"deleted", false},
	}
	for _, tt := range tests {
		if got := (&User{Status: tt.status}).IsActive(); got != tt.want {
			t.Errorf("IsActive(status=%q) = %v, want %v", tt.status, got, tt.want)
		}
	}
}
